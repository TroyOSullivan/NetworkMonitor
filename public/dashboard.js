const loadedPaths = new Set();

async function loadJSON(){
    let pathsArray;
    try{
        const response = await fetch("reports.json?time=" + Date.now());
        if (response.status === 404) return;
        if(!response.ok){
            throw new Error(`Error: ${response.status}`);
        }
        pathsArray = await response.json();

    }
    catch(error){
        console.error("Failed to load report list: ", error);
        return;
    }

    if(pathsArray.length === 0){
        const table = document.getElementById("log-table");
        if(!table){
            document.getElementById("table-container").textContent = "Waiting for Data";
        }
         return;
    }

    for(const path of pathsArray){
        if(loadedPaths.has(path)){
            continue;
        }
        try{
            const response = await fetch(path + "?time=" + Date.now());
            if(!response.ok){
                throw new Error(`Error: ${response.status}`);
            }
            const dataArray = await response.json();

            generateTableFromLogs(dataArray);
            loadedPaths.add(path);

        }
        catch(error){
            console.error("Failed to load JSON: ", error);
        }
   }
}
function generateTableFromLogs(data){
    const container = document.getElementById("table-container");
    if(!container) return;

    let table = document.getElementById("log-table");

    if(!table){

        container.textContent = "";

        if(!data || Object.keys(data).length === 0){
            container.textContent = "No Log Data";
            return;
        }

        table = document.createElement("table");

        table.id = "log-table";
        const thead = document.createElement("thead");
        const tbody = document.createElement("tbody");

        const headers = Object.keys(data);
        const headerRow = document.createElement("tr");
        headers.forEach(key => {
            const th = document.createElement("th");
            th.textContent = key;
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);
        table.appendChild(tbody);
        container.appendChild(table);

    }

    const tbody = table.querySelector("tbody");
    const headers = Object.keys(data);

    const dataRow = document.createElement("tr");
    headers.forEach(key => {
        const td = document.createElement("td");
        
        //FORMATTING
        if (key === "findings" && Array.isArray(data[key])) {

            if (data[key].length === 0) {

                td.textContent = "None";

            } else {

                data[key].forEach(finding => {

                    const findingBox = document.createElement("div");
                    findingBox.classList.add("finding");

                    const type = document.createElement("strong");

                    type.textContent = finding.type;
                    findingBox.appendChild(type);

                    if (finding.sourceIP) {

                        const source = document.createElement("div");
                        source.textContent = "Source: " + finding.sourceIP;

                        findingBox.appendChild(source);
                    }

                    if (finding.destinationIP) {

                        const destination = document.createElement("div");
                        destination.textContent = "Destination: " + finding.destinationIP;

                        findingBox.appendChild(destination);
                    }

                    if (finding.destinationPort) {

                        const port = document.createElement("div");
                        port.textContent = "Port: " + finding.destinationPort;

                        findingBox.appendChild(port);
                    }

                    if (
                        finding.packets &&
                        finding.packets.length > 0
                    ) {

                        const details = document.createElement("details");
                        const summary = document.createElement("summary");

                        summary.textContent = "Packets (" + finding.packets.length + ")";
                        details.appendChild(summary);

                        finding.packets.forEach(packet => {

                            const packetLine = document.createElement("div");

                            packetLine.classList.add("packet-line");
                            packetLine.textContent = "#" + packet.packetNumber + " | " + packet.Source + " → " + packet.Destination + " | " + packet.Protocol;

                            details.appendChild(packetLine);
                        });

                        findingBox.appendChild(details);
                    }
                    td.appendChild(findingBox);
                });
            }

        } else if (Array.isArray(data[key])) {

            td.textContent = data[key].length === 0 ? "None" : JSON.stringify(data[key]);

        } else {

            td.textContent = data[key] !== undefined ? data[key] : "";
        }
        dataRow.appendChild(td);
        //
    });

    tbody.appendChild(dataRow);
}
setTimeout(loadJSON,0);
setInterval(loadJSON, 3000);