require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const spreadsheetId = process.env.SPREADSHEET_ID;


const today = new Date().toISOString().split('T')[0];


const dataDir = path.join(process.cwd(), "data");
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
}


const todayJsonFile = path.join(dataDir, `${today}.json`);
const dbFile = path.join(dataDir, "db.json");
const filesInfoFile = path.join(dataDir, "files.json");



function parseLine(line) {
    const parts = line.split('•');
    if (parts.length >= 7) {
        const [id, host, stats, score, ports, geo, ip] = parts;
        const portMatch = ports.match(/(?:TCP|UDP):(\d+)/i);
        const port = portMatch ? parseInt(portMatch[1], 10) : 443;

        const geoParts = geo.split('~');
        const shortCountry = geoParts[0]?.trim() || '';
        const countryName = geoParts[1]?.trim() || '';
        const locationName = geoParts[2]?.trim() || '';

        return {
            hostname: host,
            ip: ip,
            port: port,
            info: stats,
            info2: geo,
            location: {
                country: countryName,
                short: shortCountry,
                name: locationName
            },
            id: id,
            key: `${ip}:${port}`
        };
    } else {
        console.debug(`Line did not match: ${line}`);
        return null;
    }
}

const KEY = Buffer.from(process.env.AES_KEY, 'utf8');
const IV = Buffer.from(process.env.AES_IV, 'utf8');

const HOSTS = process.env.HOSTS.split(',');
const PATH_URI = process.env.PATH_URI;
const UA = process.env.USER_AGENT;

const PACKAGE = process.env.PACKAGE;
const VERSION = process.env.VERSION;
const MOBILE = process.env.MOBILE;
const ADSIDS = process.env.ADSIDS;
const DEVICE_UUID = process.env.DEVICE_UUID;
const DEVICE_HASHED = process.env.DEVICE_HASHED;
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS || '45000', 10);

const md5 = (s) => crypto.createHash('md5').update(s, 'utf8').digest('hex');

function encryptAes(plaintext) {
    const cipher = crypto.createCipheriv('aes-256-cbc', KEY, IV);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return ct.toString('base64').replace(/\+/g, 'CRYPTO');
}

function decryptAes(b64) {
    const clean = b64.trim().replace(/CRYPTO/g, '+');
    const ct = Buffer.from(clean, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, IV);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

function buildParams(uuid, hashed) {
    return (
        `&unixtime=${Date.now()}` +
        `&uuid=${uuid}` +
        `&hashed=${hashed}` +
        `&package=${PACKAGE}` +
        `&version=${VERSION}` +
        `&mobile=${MOBILE}` +
        `&adsids=${ADSIDS}`
    );
}

function buildPlaintext(note, uuid, hashed) {
    return `magicnum=1&${buildParams(uuid, hashed)}&note=${note}`;
}

const https = require('https');

function httpGet(host, message) {
    return new Promise((resolve) => {
        const options = {
            host,
            path: `${PATH_URI}?message=${message}`,
            method: 'GET',
            headers: { 'User-Agent': UA, Accept: '*/*' },
            timeout: REQUEST_TIMEOUT_MS,
        };
        const req = https.request(options, (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () =>
                resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8').trim() })
            );
        });
        req.on('timeout', () => {
            req.destroy();
            resolve({ status: 0, body: '', error: 'timeout' });
        });
        req.on('error', (e) => resolve({ status: 0, body: '', error: e.message }));
        req.end();
    });
}

async function request(note, uuid, hashed) {
    const message = encryptAes(buildPlaintext(note, uuid, hashed));
    for (const host of HOSTS) {
        const { status, body, error } = await httpGet(host, message);
        // console.log(`  [${note}] ${host}: HTTP ${status}, ${body.length} bytes${error ? ' (' + error + ')' : ''}`);
        if (body.length > 50) return { host, body };
    }
    return { host: null, body: '' };
}

async function fetchData() {
    try {
        const uuid = DEVICE_UUID || crypto.randomUUID();
        const hashed = DEVICE_HASHED || md5(uuid);
        console.info(`Fetching data using new style requests...`);
        const { host, body } = await request('RELOADLIST', uuid, hashed);
        if (!body) {
            throw new Error("All hosts returned empty response");
        }
        const decryptedText = decryptAes(body);
        const obj = JSON.parse(decryptedText);
        const serversse = obj.serversse || "";
        const serversgp = obj.serversgp || "";
        const combined = `${serversse}\n${serversgp}`;
        return combined.split('\n');
    } catch (error) {
        console.error(`Error fetching data: ${error.message}`);
        return [];
    }
}


function saveDataToJson(data, filePath) {
    console.info(`Saving data to file: ${filePath}`);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 0), 'utf-8');
}


function updateDb(ipPortList, dbFile) {
    let existingData = [];
    if (fs.existsSync(dbFile)) {
        existingData = JSON.parse(fs.readFileSync(dbFile, 'utf-8'));
    }

    const updatedData = Array.from(new Set([...existingData, ...ipPortList]));
    console.info(`Updated db.json with ${updatedData.length} unique entries (removed duplicates).`);
    fs.writeFileSync(dbFile, JSON.stringify(updatedData, null, 0), 'utf-8');
}


function updateFilesInfo(dataDir, filesInfoFile) {
    console.info(`Updating files info in ${filesInfoFile}`);
    const fileData = [];

    fs.readdirSync(dataDir).forEach(fileName => {
        if (fileName.endsWith(".json") && fileName !== "db.json" && fileName !== "files.json") {
            const filePath = path.join(dataDir, fileName);
            const fileContent = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
            const uniqueIps = new Set(fileContent.map(entry => entry.key)).size;
            const byteSize = fs.statSync(filePath).size;
            const creationTime = fs.statSync(filePath).ctimeMs;

            fileData.push({
                name: fileName,
                sstpCount: uniqueIps,
                byteSize,
                creationTime
            });
        }
    });


    fileData.sort((a, b) => a.creationTime - b.creationTime);
    fileData.forEach(entry => delete entry.creationTime);

    fs.writeFileSync(filesInfoFile, JSON.stringify(fileData, null, 0), 'utf-8');
    console.info(`files.json updated with ${fileData.length} entries.`);
}

(async function main() {
    const lines = await fetchData();
    const parsedData = lines
        .filter(line => line.includes("SESSIONS"))
        .map(line => parseLine(line))
        .filter(data => data !== null);


    saveDataToJson(parsedData, todayJsonFile);

    const ipPortList = parsedData.map(entry => entry.key);
    updateDb(ipPortList, dbFile);


    updateFilesInfo(dataDir, filesInfoFile);

})();
