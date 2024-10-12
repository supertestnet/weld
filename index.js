import init, { Offer, Invoice } from "https://supertestnet.github.io/weld/boltz_bolt12.js"

window.bolt12parser = {}
window.bolt12parser.Offer = Offer;
window.bolt12parser.Invoice = Invoice;
window.bolt12parser.init = init;
