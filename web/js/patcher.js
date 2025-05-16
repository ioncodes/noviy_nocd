import init, { patch } from "../wasm/noviy_nocd.js";

const compatibilityTableData = [
    { title: "Lego Rock Raiders", file: "LegoRR.exe", crc32: "5435e147", note: undefined },
    { title: "Lego Racers 2", file: "Lego Racers 2.exe", crc32: "d0288104", note: undefined },
    { title: "Lego Alpha Team", file: "LoadComp.dll", crc32: "31e3d676", note: "Requires a Config.txt file with \"VerifyDiscVol  false\" set" },
    { title: "Lego Stunt Rally", file: "_msr.exe", crc32: "ca2ce831", note: "Requires the game to be launched via _msr.exe" },
];

let wasmLoaded = false;
let selectedFile = null;

// DOM elements
const fileInput = document.getElementById('fileInput');
const patchButton = document.getElementById('patchButton');
const statusDiv = document.getElementById('status');
const downloadLink = document.getElementById('downloadLink');
const compatibilityTable = document.getElementById('compatibilityTable');

// initialize WASM module
init().then(() => {
    wasmLoaded = true;
    console.log("WASM module loaded successfully");
    updatePatchButtonState();
}).catch((error) => {
    console.error("Failed to load WASM module:", error);
});

// populate compatibility table
compatibilityTableData.forEach(item => {
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${item.title}</td>
        <td><code>${item.file}</code></td>
        <td><code>${item.crc32}</code></td>
    `;
    compatibilityTable.appendChild(row);
});

// event listeners
fileInput.addEventListener('change', handleFileSelect);
patchButton.addEventListener('click', patchFile);

console.log = function (message) {
    statusDiv.textContent += message + '\n';
}

console.error = function (message) {
    if (message.includes('Corrupted PE buffer')) {
        statusDiv.textContent = 'Error: Selected file does not seem to be a valid executable\n';
    } else {
        statusDiv.textContent = message + '\n';
    }
}

function handleFileSelect(event) {
    selectedFile = event.target.files[0];
    statusDiv.textContent = `Selected file: ${selectedFile.name}`;
    updatePatchButtonState();
    downloadLink.classList.add('hidden');
}

function updatePatchButtonState() {
    patchButton.disabled = !(wasmLoaded && selectedFile);
}

function patchFile() {
    if (!selectedFile || !wasmLoaded) return;

    // reset status
    statusDiv.textContent = ``;

    const reader = new FileReader();

    reader.onload = function (event) {
        try {
            const arrayBuffer = event.target.result;
            const inputBytes = new Uint8Array(arrayBuffer);
            
            // patch the selected file
            const outputBytes = patch(inputBytes);

            // create a download link for the patched file
            const blob = new Blob([outputBytes], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);

            // offer download as filename.nocd.ext
            const stem = selectedFile.name.split('.')[0];
            const ext = selectedFile.name.split('.').pop();
            const downloadName = `${stem}.nocd.${ext}`;

            downloadLink.href = url;
            downloadLink.download = downloadName;
            downloadLink.classList.remove('hidden');
        } catch (error) {
            console.error(error);
        }
    };

    reader.readAsArrayBuffer(selectedFile);
}
