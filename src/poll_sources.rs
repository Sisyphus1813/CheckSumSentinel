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

use ahash::AHashSet;
use futures::future::try_join_all;
use reqwest::Client;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::path::Path;
use zip::ZipArchive;

const PERSISTENT_SOURCES: &[&str] = &[
    "https://bazaar.abuse.ch/export/txt/sha256/full/",
    "https://bazaar.abuse.ch/export/txt/md5/full/",
    "https://bazaar.abuse.ch/export/txt/sha1/full/",
];

const RECENT_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-md5-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha1-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt",
    "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "https://bazaar.abuse.ch/export/txt/md5/recent/",
    "https://bazaar.abuse.ch/export/txt/sha1/recent/",
];

const YARA_SOURCES: &[&str] =
    &["https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"];

async fn fetch_yara(client: &Client, source: &str) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.get(source).send().await?;
    let data = response.bytes().await?;
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();
        if name.ends_with(".yar") {
            let filename = Path::new(&name)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&name);
            let dest_path = format!("/var/lib/css/yara_rules/{}", filename);
            let mut dest_file = File::create(&dest_path)?;
            std::io::copy(&mut file, &mut dest_file)?;
        }
    }
    Ok(())
}

async fn fetch(
    client: &Client,
    source: &str,
) -> Result<AHashSet<String>, Box<dyn std::error::Error>> {
    let response = client.get(source).send().await?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.contains("application/zip") {
        let data = response.bytes().await?;
        let cursor = Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)?;
        let mut hashes = AHashSet::new();

        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line?.trim().to_string();
                if !line.is_empty() {
                    hashes.insert(line);
                }
            }
        }
        Ok(hashes)
    } else {
        let text = response.text().await?;
        Ok(text.lines().map(|s| s.to_string()).collect())
    }
}

pub async fn poll_yara(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let futures: Vec<_> = YARA_SOURCES
        .iter()
        .map(|source| fetch_yara(client, source))
        .collect();
    try_join_all(futures).await?;
    Ok(())
}

async fn poll_hashes(
    client: &Client,
    sources: &[&str],
) -> Result<AHashSet<String>, Box<dyn std::error::Error>> {
    let futures: Vec<_> = sources.iter().map(|source| fetch(client, source)).collect();
    let results = try_join_all(futures).await?;
    let mut combined = AHashSet::new();
    for result in results {
        combined.extend(result);
    }

    Ok(combined)
}

fn save(hashes: AHashSet<String>, persistent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let filtered: AHashSet<_> = hashes
        .into_iter()
        .filter(|hash| !hash.contains('#'))
        .collect();
    let mut sorted: Vec<_> = filtered.into_iter().collect();
    sorted.sort();
    let path = if persistent {
        "/var/lib/css/hashes/persistent_hashes.txt"
    } else {
        "/var/lib/css/hashes/hashes.txt"
    };
    let mut file = File::create(path)?;
    for hash in sorted {
        writeln!(file, "{}", hash)?;
    }
    Ok(())
}

pub async fn update(client: &Client, persistent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let persistent_path = Path::new("/var/lib/css/hashes/persistent_hashes.txt");
    if !persistent_path.exists() || persistent {
        let persistent_hashes = poll_hashes(client, PERSISTENT_SOURCES).await?;
        save(persistent_hashes, true)?;
    }
    let hashes = poll_hashes(client, RECENT_SOURCES).await?;
    save(hashes, false)?;
    Ok(())
}
