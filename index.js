import init, { Offer, Invoice } from "https://supertestnet.github.io/weld/boltz_bolt12.js"

const run = async () => {
  const bolt12 = await init("https://supertestnet.github.io/weld/boltz_bolt12_bg.wasm");

  const offer = new Offer(
      "lno1zrxq8pjw7qjlm68mtp7e3yvxee4y5xrgjhhyf2fxhlphpckrvevh50u0qtuzuc7vrxw3ptvmvzs7lqmyp94rhmfdg6gpef65rs2xxl2mzr2ksqszz0xxdd9y6653lwugyjqg6nwjerz4wcdskllmkp9fl4kp4d5z0hfqqvlxj7wm32qk0pavw6cr3kfn6unhzy9r25vlp4nmmy0gfck4ur7qk0xz43lhmnlx59qfxmdh6ue6y65s7rw4qdtdltt5gzratf3hnr668laqtcrk5tyzfz8a8ckq4dlpd40alv646qqsf6pgykhxlayyswqmjffpgehjjs"
    );
    console.log(offer.id)
  offer.free();
};

window.bolt12parser = {}
window.bolt12parser.Offer = Offer;
window.bolt12parser.Invoice = Invoice;
window.bolt12parser.run = run;
window.bolt12parser.bolt12 = await init("https://supertestnet.github.io/weld/boltz_bolt12_bg.wasm");
window.bolt12parser.init = init;

run();
