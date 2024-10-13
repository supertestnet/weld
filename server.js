/*

THESE NEXT LINES ARE CUSTOMIZABLE SETTINGS

*/

var invoicemac = "";
var adminmac = "";
var lndendpoint = ""; //e.g. https://127.0.0.1:8080 or https://cloud-59.voltage.com
var min_amount = 1;
var max_amount = 1000000;
var fee_type = "percentage"; //alternative: "absolute"
var fee = 5; //if fee type is absolute, this integer is a flat rate, e.g. you will get 5 sats per weld; otherwise you get a rate corresponding to e.g. 5% of each weld

/*

END OF CUSTOMIZABLE SETTINGS - DON'T TOUCH ANYTHING AFTER THIS POINT

*/

var bolt12s_to_save = {}

var { exec } = require( 'child_process' );
var request = require( 'request' );
var http = require( 'http' );
var url = require( 'url' );

var bytesToHex = bytes => bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" );

var crypto = require( 'crypto' );
var nobleSecp256k1 = require( 'noble-secp256k1' );
var WebSocket = require( 'ws' ).WebSocket;
var browserifyCipher = require( 'browserify-cipher' );
var super_nostr = {
    sockets: {},
    hexToBytes: hex => Uint8Array.from( hex.match( /.{1,2}/g ).map( byte => parseInt( byte, 16 ) ) ),
    bytesToHex: bytes => bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" ),
    base64ToHex: str => {
        var raw = atob( str );
        var result = '';
        var i; for ( i=0; i<raw.length; i++ ) {
            var hex = raw.charCodeAt( i ).toString( 16 );
            result += hex.length % 2 ? '0' + hex : hex;
        }
        return result.toLowerCase();
    },
    getPrivkey: () => super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ),
    getPubkey: privkey => nobleSecp256k1.getPublicKey( privkey, true ).substring( 2 ),
    sha256: async text_or_bytes => {if ( typeof text_or_bytes === "string" ) text_or_bytes = ( new TextEncoder().encode( text_or_bytes ) );return super_nostr.bytesToHex( await nobleSecp256k1.utils.sha256( text_or_bytes ) )},
    waitSomeSeconds: num => {
        var num = num.toString() + "000";
        num = Number( num );
        return new Promise( resolve => setTimeout( resolve, num ) );
    },
    getEvents: async ( relay_or_socket, ids, authors, kinds, until, since, limit, etags, ptags ) => {
        var socket_is_permanent = false;
        if ( typeof relay_or_socket !== "string" ) socket_is_permanent = true;
        if ( typeof relay_or_socket === "string" ) var socket = new WebSocket( relay_or_socket );
        else var socket = relay_or_socket;
        var events = [];
        var opened = false;
        if ( socket_is_permanent ) {
            var subId = super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 16 );
            var filter  = {}
            if ( ids ) filter.ids = ids;
            if ( authors ) filter.authors = authors;
            if ( kinds ) filter.kinds = kinds;
            if ( until ) filter.until = until;
            if ( since ) filter.since = since;
            if ( limit ) filter.limit = limit;
            if ( etags ) filter[ "#e" ] = etags;
            if ( ptags ) filter[ "#p" ] = ptags;
            var subscription = [ "REQ", subId, filter ];
            socket.send( JSON.stringify( subscription ) );
            return;
        }
        socket.addEventListener( 'message', async function( message ) {
            var [ type, subId, event ] = JSON.parse( message.data );
            var { kind, content } = event || {}
            if ( !event || event === true ) return;
            events.push( event );
        });
        socket.addEventListener( 'open', async function( e ) {
            opened = true;
            var subId = super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 16 );
            var filter  = {}
            if ( ids ) filter.ids = ids;
            if ( authors ) filter.authors = authors;
            if ( kinds ) filter.kinds = kinds;
            if ( until ) filter.until = until;
            if ( since ) filter.since = since;
            if ( limit ) filter.limit = limit;
            if ( etags ) filter[ "#e" ] = etags;
            if ( ptags ) filter[ "#p" ] = ptags;
            var subscription = [ "REQ", subId, filter ];
            socket.send( JSON.stringify( subscription ) );
        });
        var loop = async () => {
            if ( !opened ) {
                await super_nostr.waitSomeSeconds( 1 );
                return await loop();
            }
            var len = events.length;
            await super_nostr.waitSomeSeconds( 1 );
            if ( len !== events.length ) return await loop();
            socket.close();
            return events;
        }
        return await loop();
    },
    prepEvent: async ( privkey, msg, kind, tags ) => {
        pubkey = super_nostr.getPubkey( privkey );
        if ( !tags ) tags = [];
        var event = {
            "content": msg,
            "created_at": Math.floor( Date.now() / 1000 ),
            "kind": kind,
            "tags": tags,
            "pubkey": pubkey,
        }
        var signedEvent = await super_nostr.getSignedEvent( event, privkey );
        return signedEvent;
    },
    sendEvent: ( event, relay_or_socket ) => {
        var socket_is_permanent = false;
        if ( typeof relay_or_socket !== "string" ) socket_is_permanent = true;
        if ( typeof relay_or_socket === "string" ) var socket = new WebSocket( relay_or_socket );
        else var socket = relay_or_socket;
        if ( !socket_is_permanent ) {
            socket.addEventListener( 'open', async () => {
                socket.send( JSON.stringify( [ "EVENT", event ] ) );
                setTimeout( () => {socket.close();}, 1000 );
            });
        } else {
            socket.send( JSON.stringify( [ "EVENT", event ] ) );
        }
        return event.id;
    },
    getSignedEvent: async ( event, privkey ) => {
        var eventData = JSON.stringify([
            0,
            event['pubkey'],
            event['created_at'],
            event['kind'],
            event['tags'],
            event['content'],
        ]);
        event.id = await super_nostr.sha256( eventData );
        event.sig = await nobleSecp256k1.schnorr.sign( event.id, privkey );
        return event;
    },
    encrypt: ( privkey, pubkey, text ) => {
        var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );
        var iv = crypto.getRandomValues( new Uint8Array( 16 ) );
        var cipher = browserifyCipher.createCipheriv( 'aes-256-cbc', super_nostr.hexToBytes( key ), iv );
        var encryptedMessage = cipher.update(text,"utf8","base64");
        emsg = encryptedMessage + cipher.final( "base64" );
        var uint8View = new Uint8Array( iv.buffer );
        var decoder = new TextDecoder();
        return emsg + "?iv=" + btoa( String.fromCharCode.apply( null, uint8View ) );
    },
    decrypt: ( privkey, pubkey, ciphertext ) => {
        var [ emsg, iv ] = ciphertext.split( "?iv=" );
        var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );
        var decipher = browserifyCipher.createDecipheriv(
            'aes-256-cbc',
            super_nostr.hexToBytes( key ),
            super_nostr.hexToBytes( super_nostr.base64ToHex( iv ) )
        );
        var decryptedMessage = decipher.update( emsg, "base64" );
        dmsg = decryptedMessage + decipher.final( "utf8" );
        return dmsg;
    },
    newPermanentConnection: ( relay, listenFunction, handleFunction ) => {
        var socket_id = super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 16 );
        super_nostr.sockets[ socket_id ] = {socket: null, connection_failure: false}
        super_nostr.connectionLoop( 0, relay, socket_id, listenFunction, handleFunction );
        return socket_id;
    },
    connectionLoop: async ( tries = 0, relay, socket_id, listenFunction, handleFunction ) => {
        var socketRetrieverFunction = socket_id => {
            return super_nostr.sockets[ socket_id ][ "socket" ];
        }
        var socketReplacerFunction = ( socket_id, socket ) => {
            super_nostr.sockets[ socket_id ][ "socket" ] = socket;
            super_nostr.sockets[ socket_id ][ "connection_failure" ] = false;
        }
        var socketFailureCheckerFunction = socket_id => {
            return super_nostr.sockets[ socket_id ][ "connection_failure" ];
        }
        var socketFailureSetterFunction = socket_id => {
            return super_nostr.sockets[ socket_id ][ "connection_failure" ] = true;
        }
        if ( socketFailureCheckerFunction( socket_id ) ) return console.log( `your connection to nostr failed and could not be restarted, please restart the app` );
        var socket = socketRetrieverFunction( socket_id );
        if ( !socket ) {
            var socket = new WebSocket( relay );
            socket.addEventListener( 'message', handleEvent );
            socket.addEventListener( 'open', ()=>{listenFunction( socket );} );
            socketReplacerFunction( socket_id, socket );
        }
        if ( socket.readyState === 1 ) {
            await super_nostr.waitSomeSeconds( 1 );
            return super_nostr.connectionLoop( 0, relay, socket_id, listenFunction, handleFunction );
        }
        // if there is no connection, check if we are still connecting
        // give it two chances to connect if so
        if ( socket.readyState === 0 && !tries ) {
            await super_nostr.waitSomeSeconds( 1 );
            return super_nostr.connectionLoop( 1, relay, socket_id, listenFunction, handleFunction );
        }
        if ( socket.readyState === 0 && tries ) {
            socketFailureSetterFunction( socket_id );
            return;
        }
        // otherwise, it is either closing or closed
        // ensure it is closed, then make a new connection
        socket.close();
        await super_nostr.waitSomeSeconds( 1 );
        socket = new WebSocket( relay );
        socket.addEventListener( 'message', handleFunction );
        socket.addEventListener( 'open', ()=>{listenFunction( socket );} );
        socketReplacerFunction( socket_id, socket );
        await super_nostr.connectionLoop( 0, relay, socket_id, listenFunction, handleFunction );
    }
}

var relay = "wss://nostrue.com";
var privkey = bytesToHex( nobleSecp256k1.utils.randomPrivateKey() );
var pubkey = nobleSecp256k1.getPublicKey( privkey, true ).substring( 2 );
console.log( "pubkey:", pubkey );

var listenFunction = async ( socket ) => {
    var subId = super_nostr.bytesToHex( nobleSecp256k1.utils.randomPrivateKey() ).substring( 0, 16 );
    var filter  = {}
    filter.kinds = [ 4 ];
    filter.since = Math.floor( Date.now() / 1000 );
    filter[ "#p" ] = [ pubkey ];
    var subscription = [ "REQ", subId, filter ];
    socket.send( JSON.stringify( subscription ) );
}
var handleEvent = async message => {
    var [ type, subId, event ] = JSON.parse( message.data );
    var { kind, content } = event || {}
    if ( !event || event === true ) return;
    // try {
    	event.content = super_nostr.decrypt( privkey, event.pubkey, event.content );
    // } catch ( e ) {}
    console.log( event );
    try {
	    var json = JSON.parse( event.content );
    } catch ( e ) {console.log( "error", event );return;}
    if ( json[ "bolt12" ] && json[ "amt" ] ) {
		var offer = json[ "bolt12" ];
		var amount = Number( json[ "amt" ] );
		if ( !amount ) {
			return sendResponse( response, '{"error": "method not supported"}', 200, {'Content-Type': 'text/plain'} );
		}
		var command = `lndk-cli --network=mainnet get-invoice ${offer} ${amount * 1000}`;
		var obj = {}
		exec( command, async ( error, stdout, stderr ) => {
		    if (error) {
		        return console.log( `{"error": "${error.message}"}` );
		    }
		    if (stderr) {
		        return console.log(`stderr: ${stderr}`);
		    }
		    var returned_data = stdout;
		    if ( !stdout.startsWith( "Invoice: GetInvoiceResponse" ) ) console.log( 'error, try again' );
		    returned_data = stdout.substring( 30, stdout.length - 4 );
		    var idx_of_key = returned_data.indexOf( "invoice_hex_str" );
		    var rest = returned_data.substring( idx_of_key );
		    var idx_of_comma = rest.indexOf( "," );
		    var key_value = rest.substring( 0, idx_of_comma ).split( ": " );
		    obj[ key_value[ 0 ] ] = key_value[ 1 ];
		    var idx_of_key = returned_data.indexOf( "amount_msats" );
		    var rest = returned_data.substring( idx_of_key );
		    var idx_of_comma = rest.indexOf( "," );
		    var key_value = rest.substring( 0, idx_of_comma ).split( ": " );
		    obj[ key_value[ 0 ] ] = Number( key_value[ 1 ] );
		    var idx_of_key = returned_data.indexOf( "payment_hash" );
		    var rest = returned_data.substring( idx_of_key );
		    var idx_of_comma = rest.indexOf( "\}\)\," );
		    var key_value = rest.substring( 0, idx_of_comma ).split( ": " );
		    obj[ key_value[ 0 ] ] = bytesToHex( JSON.parse( key_value[ 2 ].substring( 0, key_value[ 2 ].length - 1 ) ) );
		    var idx_of_key = returned_data.indexOf( "cltv_expiry_delta" );
		    var rest = returned_data.substring( idx_of_key );
		    var idx_of_comma = rest.indexOf( "," );
		    var key_value = rest.substring( 0, idx_of_comma ).split( ": " );
		    obj[ key_value[ 0 ] ] = Number( key_value[ 1 ] );
		    obj[ "bolt12_invoice" ] = "todo";
		    new_obj = JSON.parse( JSON.stringify( obj ) );
		    bolt12s_to_save[ obj[ "payment_hash" ] ] = new_obj;
		    delete obj[ "invoice_hex_str" ];
		    var msg = JSON.stringify( obj );
		    var emsg = super_nostr.encrypt( privkey, event.pubkey, msg );
		    var new_event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", event.pubkey ] ] );
		    console.log( new_event );
		    super_nostr.sendEvent( new_event, relay );
		});
    } else if ( json[ "amt" ] && json[ "pmthash" ] && json[ "timelock" ] ) {
		try {
			var bolt12_to_pay = bolt12s_to_save[ json[ "pmthash" ] ];
			var amt_i_receive = Number( json[ "amt" ] );
			var timelock_that_must_exceed_other = Number( json[ "timelock" ] );
			if ( !( json[ "pmthash" ] in bolt12s_to_save ) ) return console.log( '{"error": "bolt12 not found"}' );
			var bolt12_to_pay = JSON.parse( JSON.stringify( bolt12s_to_save[ json[ "pmthash" ] ] ) );
			delete bolt12s_to_save[ json[ "pmthash" ] ]
			if ( amt_i_receive * 1000 <= bolt12_to_pay[ "amount_msats" ] ) return console.log( '{"error": "you need to pay me more"}' );
			if ( timelock_that_must_exceed_other <= bolt12_to_pay[ "cltv_expiry_delta" ] ) return console.log( '{"error": "your timelock is too short"}' );
			if ( !( json[ "pmthash" ] in bolt12s_to_save ) ) bolt12s_to_save[ json[ "pmthash" ] ] = {}
			if ( !( "hodl_invoice" in bolt12s_to_save[ json[ "pmthash" ] ] ) ) {
				var invoice = await getHodlInvoice( amt_i_receive, json[ "pmthash" ], timelock_that_must_exceed_other );
				bolt12s_to_save[ json[ "pmthash" ] ][ "hodl_invoice" ] = invoice;
			} else {
				var invoice = bolt12s_to_save[ json[ "pmthash" ] ][ "hodl_invoice" ];
			}

			var msg = JSON.stringify({"bolt11": `${invoice}`, pmthash: json[ "pmthash" ]});
			var emsg = super_nostr.encrypt( privkey, event.pubkey, msg );
			var new_event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", event.pubkey ] ] );
			console.log( new_event );
			super_nostr.sendEvent( new_event, relay );

			console.log( 'listening for invoice to be paid...' );
			console.log( bolt12_to_pay );
			var state = await checkInvoiceStatus( json[ "pmthash" ] );
			if ( state !== "ACCEPTED" ) return console.log( `so sad, it didn't work out` );
			var command = `lndk-cli --network=mainnet pay-invoice ${bolt12_to_pay[ "invoice_hex_str" ]} ${bolt12_to_pay[ "amount_msats" ]}`;
			exec( command, async ( error, stdout, stderr ) => {
			    if (error) {
			        return console.log(`error: ${error.message}`);
			    }
			    if (stderr) {
			        return console.log(`stderr: ${stderr}`);
			    }
    		    var returned_data = stdout;
    		    console.log( returned_data );
	    		if ( returned_data.startsWith( `Successfully paid for offer` ) ) {
	    			// var status = await checkPaymentStatus( json[ "pmthash" ] );
	    			var new_cmd = `lncli trackpayment ${json[ "pmthash" ]}`;
	    			exec( new_cmd, ( error2, stdout2, stderr2 ) => {
	    			    if (error) {
	    			        return console.log(`error: ${error2.message}`);
	    			    }
	    			    if (stderr) {
	    			        return console.log(`stderr: ${stderr2}`);
	    			    }
	    			    var new_data = stdout2;
	    			    console.log( new_data );
	    			    var preimage = new_data.substring( new_data.indexOf( "preimage: " ) + 10 );
	    			    preimage = preimage.replaceAll( "\n", "" );
	    			    console.log( preimage );
	    			    settleHoldInvoice( preimage );
	    			});
	    		}
			});
		} catch ( e ) {
			return console.log( '{"error": "method not supported"}' );
		}
    } else if ( json[ "check_status" ] && json[ "pmthash" ] ) {
		try {
			var status = await checkInvoiceStatusWithoutLoop( json[ "pmthash" ] );
			var msg = JSON.stringify( status );
			var emsg = super_nostr.encrypt( privkey, event.pubkey, msg );
			var new_event = await super_nostr.prepEvent( privkey, emsg, 4, [ [ "p", event.pubkey ] ] );
			console.log( new_event );
			super_nostr.sendEvent( new_event, relay );
		} catch( e ) {
			return console.log( '{"error": "method not supported"}' );
		}
    } else {
    	console.log( event );
    }
}

var init = async () => {
	var socket_id = await super_nostr.newPermanentConnection( relay, listenFunction, handleEvent );
	var socket = super_nostr.sockets[ socket_id ];
}
init();

async function getHodlInvoice( amount, hash, expiry = 40 ) {
    var invoice = "";
    var macaroon = invoicemac;
    var endpoint = lndendpoint + "/v2/invoices/hodl";
    let requestBody = {
        hash: Buffer.from( hash, "hex" ).toString( "base64" ),
        value: amount.toString(),
        cltv_expiry: expiry.toString(),
        private: true,
    }
    let options = {
        url: endpoint,
        // Work-around for self-signed certificates.
        rejectUnauthorized: false,
        json: true,
        headers: {
            'Grpc-Metadata-macaroon': macaroon,
        },
        form: JSON.stringify(requestBody),
    }
    request.post(options, function(error, response, body) {
        invoice = body[ "payment_request" ];
        // console.log( "hodl invoice:", body );
    });
    async function isNoteSetYet( note_i_seek ) {
	    return new Promise( function( resolve, reject ) {
	        if ( note_i_seek == "" ) {
	            setTimeout( async function() {
	                var msg = await isNoteSetYet( invoice );
	                resolve( msg );
	            }, 100 );
	        } else {
	              resolve( note_i_seek );
	        }
	    });
    }
    async function getTimeoutData() {
        var invoice_i_seek = await isNoteSetYet( invoice );
        return invoice_i_seek;
	}
    var returnable = await getTimeoutData();
    return returnable;
}

async function settleHoldInvoice( preimage ) {
    var settled = "";
    const macaroon = invoicemac;
    const endpoint = lndendpoint;
    let requestBody = {
        preimage: Buffer.from( preimage, "hex" ).toString( "base64" )
    }
    let options = {
        url: endpoint + '/v2/invoices/settle',
        // Work-around for self-signed certificates.
        rejectUnauthorized: false,
        json: true,
        headers: {
            'Grpc-Metadata-macaroon': macaroon,
        },
        form: JSON.stringify( requestBody ),
    }
    request.post( options, function( error, response, body ) {
        if ( body.toString().includes( "{" ) ) {
            settled = "true";
        } else {
            settled = "false";
        }
    });
    async function isNoteSetYet( note_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( note_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isNoteSetYet( settled );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( note_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var invoice_i_seek = await isNoteSetYet( settled );
        return invoice_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function checkInvoiceStatusWithoutLoop( hash ) {
    var status = "";
    const macaroon = invoicemac;
    const endpoint = lndendpoint;
    let options = {
        url: endpoint + '/v1/invoice/' + hash,
        // Work-around for self-signed certificates.
        rejectUnauthorized: false,
        json: true,
        headers: {
            'Grpc-Metadata-macaroon': macaroon,
        },
    }
    request.get( options, function( error, response, body ) {
        status = body[ "state" ];
        console.log( "status:", status );
    });
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( data_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isDataSetYet( status );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( status );
        return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function checkInvoiceStatus( hash ) {
    var status = "";
    const macaroon = invoicemac;
    const endpoint = lndendpoint;
    let options = {
        url: endpoint + '/v1/invoice/' + hash,
        // Work-around for self-signed certificates.
        rejectUnauthorized: false,
        json: true,
        headers: {
            'Grpc-Metadata-macaroon': macaroon,
        },
    }
    request.get( options, function( error, response, body ) {
        status = body[ "state" ];
        console.log( "status:", status );
    });
    var time = 0;
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( data_i_seek != "ACCEPTED" ) {
                setTimeout( async function() {
                    time = time + 1;
                    console.log( "time:", time )
                    if ( time == 1000 || time > 1000 ) {
                        resolve( "failure" );
						return;
                    }
                    console.log( "checking if buyer sent payment yet..." );
                    status = await checkInvoiceStatusWithoutLoop( hash );
                    var msg = await isDataSetYet( status );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( status );
        return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function checkPaymentStatus( hash ) {
    var payment_preimage = "";
    const macaroon = adminmac;
    const endpoint = lndendpoint;
    let options = {
        url: endpoint + '/v2/router/track/' + Buffer.from( hash, "hex" ).toString( "base64" ),
        // Work-around for self-signed certificates.
        rejectUnauthorized: false,
        json: true,
        headers: {
            'Grpc-Metadata-macaroon': macaroon,
        },
    }
    request.get( options, function( error, response, body ) {
    	console.log( error );
    	console.log( response );
    	console.log( body );
        payment_preimage = body[ "payment_preimage" ];
        console.log( "payment_preimage:", payment_preimage );
    });
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( data_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isDataSetYet( payment_preimage );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( payment_preimage );
        return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}
