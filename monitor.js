const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const SAVE_FOLDER = path.join(__dirname,"public","MonitorLogs");
if (!fs.existsSync(SAVE_FOLDER)) {
    fs.mkdirSync(SAVE_FOLDER, {
        recursive: true
    });
}

const CAPTURE_TIME = 30;
const START_TIME = Date.now();
let TIME_PASSED = (Date.now() - START_TIME) / 1000;

const tsharkPath = process.env.TSHARK_PATH || "tshark";
const REPORT_LIST_PATH = path.join(__dirname, "public", "reports.json");
let count = 0;
function JSONSaving(FILE_TIME, TWIN, PCAPNGSAVE_FILE_PATH, TODAY){

    const JSONFILE_NAME = "Traffic-" + FILE_TIME + ".json";
    const JSONSAVE_FILE_PATH = TWIN + "\\" + JSONFILE_NAME;

    const tsharkJSON = spawn(tsharkPath, [
        '-r', PCAPNGSAVE_FILE_PATH,
        "-T", "json"
    ]);

    const outputFile = fs.createWriteStream(JSONSAVE_FILE_PATH);

    tsharkJSON.stdout.pipe(outputFile);

    tsharkJSON.stderr.on("data", (data) => {
        console.log(data.toString());
    });

    outputFile.on("finish", () => {
        count++;
        console.log("JSON FILE created: " + count);
        analyzeJSON(JSONSAVE_FILE_PATH, TWIN, FILE_TIME, TODAY);
    })
}
function analyzeJSON(JSONSAVE_FILE_PATH, TWIN, FILE_TIME, TODAY){
    fs.readFile(JSONSAVE_FILE_PATH, "utf-8", (error, data) => {
        if(error){
            console.log("Could not read JSON file.");
            console.log(error);
            return;
        }

        let packets;

        try{
            packets = JSON.parse(data);
        }
        catch(error){
            console.log("Could not parse JSON file.");
            console.log(error);
            return;
        }

        console.log("Wireshark grabbed " + packets.length + " packets.");

        const suspiciousPorts = [
            "21",
            "23",
            "2323",
            "3389",
            "4444"
        ];

        const findings = [];
        const portsByIP = new Map();
        const destinationsByIP = new Map();
        const connectionsByIP = new Map();
        const dnsQueriesByIP = new Map();
        const dnsFailuresByIP = new Map();

        for(const packet of packets){
            const layers = packet?._source?.layers;

            if(!layers){
                continue;
            }

            if(!layers.ip){
                continue;
            }

            const sourceIP = layers.ip["ip.src"];
            const destinationIP = layers.ip["ip.dst"];
            const sourcePort = layers.tcp?.["tcp.srcport"] ?? layers.udp?.["udp.srcport"];
            const destinationPort = layers.tcp?.["tcp.dstport"] ?? layers.udp?.["udp.dstport"];

            let protocol;
            const protocolStack = layers.frame?.["frame.protocols"];

            if(protocolStack){
                const protocols = protocolStack.split(":");
                protocol = protocols[protocols.length - 1];
            }

            if(layers.dns){
                const dnsFlags = layers.dns?.["dns.flags_tree"];
                const DNS_RESPONSE = dnsFlags?.["dns.flags.response"];
                const DNS_RCODE = dnsFlags?.["dns.flags.rcode"];
                if(DNS_RESPONSE == "0"){
                    if(!dnsQueriesByIP.has(sourceIP)){
                        dnsQueriesByIP.set(sourceIP, {count: 0, packets:[]});
                    }

                    dnsQueriesByIP.get(sourceIP).count++;

                    dnsQueriesByIP.get(sourceIP).packets.push({
                        packetNumber: layers.frame?.["frame.number"],
                        Source: sourceIP + ":" + sourcePort,
                        Destination: destinationIP + ":" + destinationPort,
                        Protocol: protocol
                    });
                }

                if(DNS_RESPONSE == "1" && DNS_RCODE != "0"){
                    if(!dnsFailuresByIP.has(destinationIP)){
                        dnsFailuresByIP.set(destinationIP, {count: 0, packets:[]});
                    }

                    dnsFailuresByIP.get(destinationIP).count++;

                    dnsFailuresByIP.get(destinationIP).packets.push({
                        packetNumber: layers.frame?.["frame.number"],
                        Source: sourceIP + ":" + sourcePort,
                        Destination: destinationIP + ":" + destinationPort,
                        Protocol: protocol
                    });
                }
            }
            if(!layers.tcp){
                continue;
            }
            const SYN = layers.tcp?.["tcp.flags_tree"]?.["tcp.flags.syn"];
            const ACK = layers.tcp?.["tcp.flags_tree"]?.["tcp.flags.ack"];

            //CHECK FOR SUSPICIOUS PORTS
            if(suspiciousPorts.includes(
                destinationPort
            )){
                console.log("WARNING: Access to suspicious port detected at: " + sourceIP + ":" + sourcePort + " => " + destinationIP + ":" + destinationPort);
                findings.push({
                    type: "Suspicious Port",
                    sourceIP: sourceIP,
                    sourcePort: sourcePort,
                    destinationIP: destinationIP,
                    destinationPort: destinationPort,
                    packets: [{packetNumber:layers.frame?.["frame.number"],
                            Source: sourceIP + ":" + sourcePort,
                            Destination: destinationIP + ":" + destinationPort,
                            Protocol: protocol}]
                });

            }
            if(SYN == "1" && ACK == "0"){
                //CHECK FOR PORT SCANS
                if(!portsByIP.has(sourceIP)){
                    portsByIP.set(sourceIP, {ports: new Set(),packets:[]});
                }

                const scanData = portsByIP.get(sourceIP);
                scanData.ports.add(destinationPort);
                scanData.packets.push({
                    packetNumber: layers.frame?.["frame.number"],
                    Source: sourceIP + ":" + sourcePort,
                    Destination: destinationIP + ":" + destinationPort,
                    Protocol: protocol
                });

                //CHECK FOR IP SCANS
                if(!destinationsByIP.has(sourceIP)){
                    destinationsByIP.set(sourceIP, {destinations: new Set(),packets:[]});
                }
                destinationsByIP.get(sourceIP).destinations.add(destinationIP);

                destinationsByIP.get(sourceIP).packets.push({
                    packetNumber: layers.frame?.["frame.number"],
                    Source: sourceIP + ":" + sourcePort,
                    Destination: destinationIP + ":" + destinationPort,
                    Protocol: protocol
                });

                if(!connectionsByIP.has(sourceIP)){
                    connectionsByIP.set(sourceIP, {count: 0, packets:[]});
                }
                connectionsByIP.get(sourceIP).count++;

                connectionsByIP.get(sourceIP).packets.push({
                    packetNumber: layers.frame?.["frame.number"],
                    Source: sourceIP + ":" + sourcePort,
                    Destination: destinationIP + ":" + destinationPort,
                    Protocol: protocol
                });
            }
        }
        //PORT SCAN CHECK
        for(const [ip,data] of portsByIP){
                if(data.ports.size >= 3){
                    console.log("WARNING: Possible port scan at:");
                    console.log("Source IP: " + ip);

                    console.log("Unique destination ports: " + data.ports.size);
                    console.log("AT: " + Array.from(data.ports).join(", "));

                    findings.push({
                        type: "Possible Port Scan",
                        sourceIP: ip,
                        uniqueDestinationPorts: data.ports.size,
                        ports: Array.from(data.ports),
                        packets: data.packets
                    });
                }
        }
        //DESTINATION CHECK
        for(const [ip,data] of destinationsByIP){
                if(data.destinations.size >= 3){
                    console.log("WARNING: Large number of destinations.");
                    console.log("Source IP: " + ip);

                    console.log("Unique destinations: " + data.destinations.size);
                    console.log("AT: " + Array.from(data.destinations).join(", "));

                    findings.push({
                        type: "Many Destination IPs",
                        sourceIP: ip,
                        uniqueDestinations: data.destinations.size,
                        destinations: Array.from(data.destinations),
                        packets: data.packets
                    });
                }
        }
        //CONNECTION BURST CHECK
        for(const[ip,data] of connectionsByIP){
            if(data.count >= 3){
                console.log("WARNING: Large number of connections.");
                console.log("Source ip: " + ip);
                console.log("Connection attempts: " + data.count);

                findings.push({
                    type: "Connection Burst",
                    sourceIP: ip,
                    connectionAttempts: data.count,
                    packets: data.packets
                });
            }
        }
        //DNS QUERY CHECK
        for(const[ip, data] of dnsQueriesByIP){
            if(data.count >= 5){
                console.log("WARNING: Large DNS query burst.");
                console.log("Source ip: " + ip);
                console.log("Queries: " + data.count);

                findings.push({
                    type: "DNS Query Burst",
                    sourceIP: ip,
                    dnsQueries: data.count,
                    packets: data.packets
                });
            }
        }
        //DNS FAILURE CHECK
        for(const[ip, data] of dnsFailuresByIP){
            if(data.count >= 3){
                console.log("WARNING: Large number of failed DNS requests.");
                console.log("Source ip: " + ip);
                console.log("Failures: " + data.count);

                findings.push({
                    type: "DNS Failure Burst",
                    sourceIP: ip,
                    dnsFailures: data.count,
                    packets: data.packets
                });
            }
        }
        
        console.log("Analyzed " + packets.length + " packets.");

        //SECURITY REPORT CREATION
        const report = {
            captureTime: FILE_TIME,
            captureDurationSeconds: CAPTURE_TIME,
            packetsAnalyzed: packets.length,
            numberOfFindings: findings.length,
            findings: findings,
        }

        const SECURITY_FILE_NAME = "SecurityReport-" + FILE_TIME + ".json";
        const SECURITY_FILE_PATH = path.join(TWIN, SECURITY_FILE_NAME);

        const SECURITY_FILE_NAME_PUSH = "./MonitorLogs/" + TODAY + "/TWIN-" + FILE_TIME + "/" + SECURITY_FILE_NAME;

        fs.writeFileSync(
            SECURITY_FILE_PATH,
            JSON.stringify(report, null, 4)
        );

        const reportPaths = fs.existsSync(REPORT_LIST_PATH) ? JSON.parse(fs.readFileSync(REPORT_LIST_PATH, "utf8")) : [];
        reportPaths.push(SECURITY_FILE_NAME_PUSH)

        fs.writeFileSync(
            REPORT_LIST_PATH,
            JSON.stringify(reportPaths, null, 4)
        );
    })
    capture();
}
function capture(){

    //FOLDER DATE
    const now = new Date();
    const TODAY = (now.getMonth() + 1) + "-" + now.getDate() + "-" + now.getFullYear();
    //

    const DAY_FOLDER = path.join(SAVE_FOLDER, TODAY);
    if(!fs.existsSync(DAY_FOLDER)){
        fs.mkdirSync(DAY_FOLDER, {
            recursive: true
        });
    }

    //FILE DATE
    const FILE_TIME = now.getHours() + "-" + now.getMinutes() + "-" + now.getSeconds();
    const FILE_NAME = "Traffic-" + FILE_TIME + ".pcapng";
    //

    const TWIN = path.join(DAY_FOLDER, "TWIN-", FILE_TIME);
    if(!fs.existsSync(TWIN)){
        fs.mkdirSync(TWIN, {
            recursive: true
        });
    }

    const PCAPNGSAVE_FILE_PATH = path.join(TWIN, FILE_NAME);

    //PROCESS OF SAVING
    const tshark = spawn(tsharkPath, [
        '-i', '9',
        '-a', `duration:${CAPTURE_TIME}`,
        '-w', PCAPNGSAVE_FILE_PATH
    ]);

    tshark.stderr.on("data", (data) => {
        console.log(data.toString());
    });

    tshark.on("close", () => {
        TIME_PASSED = (Date.now() - START_TIME) / 1000;
        console.log("Wireshark ran for " + TIME_PASSED + " seconds.");
        JSONSaving(FILE_TIME, TWIN, PCAPNGSAVE_FILE_PATH, TODAY);
    });
    

}
capture();
