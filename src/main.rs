// Freeoxide Tunnel (`ft`) — expose local/static services through temporary tunnels.
//
// Module root. The CLI dispatch and command implementations are wired up by the
// implementation workflow; the modules below are the frozen core contract.

mod error;
mod model;
mod name;
mod port;
mod proc;
mod registry;
mod state;

fn main() {
    // CLI dispatch is added once the command modules land.
}
