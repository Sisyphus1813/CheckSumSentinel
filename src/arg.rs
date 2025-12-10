// Copyright (C) 2025  Sisyphus1813
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "CheckSumSentinel")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a file
    Scan {
        /// Path to file
        file: String,
    },
    /// Update Hashes and/or Yara rules
    Update {
        /// Update recent hashes
        #[arg(short, long)]
        recent: bool,

        /// Update persistent hashes
        #[arg(short, long)]
        persistent: bool,

        /// Update Yara rules
        #[arg(short, long)]
        yara: bool,
    },
    /// Watch directories specified in /etc/css/
    Watch,
}
