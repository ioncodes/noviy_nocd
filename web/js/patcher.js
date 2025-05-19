import init, { patch } from '../wasm/noviy_nocd.js';

const compatibilityTableData = [
    { title: 'Lego Rock Raiders', file: 'LegoRR.exe', crc32: '5435e147', note: undefined },
    { title: 'Lego Racers 2', file: 'Lego Racers 2.exe', crc32: 'd0288104', note: undefined },
    { title: 'Lego Alpha Team', file: 'LoadComp.dll', crc32: '31e3d676', note: 'Requires a Config.txt file with "VerifyDiscVol false" set' },
    { title: 'Lego Stunt Rally', file: '_msr.exe', crc32: 'ca2ce831', note: 'Requires the game to be launched via _msr.exe' },
];

let wasmLoaded = false;
let fileBuffer = null;

// DOM elements
const fileInput = document.getElementById('fileInput');
const patchButton = document.getElementById('patchButton');
const statusDiv = document.getElementById('status');
const downloadLink = document.getElementById('downloadLink');
const compatibilityTable = document.getElementById('compatibilityTable');
const alertContainer = document.getElementById('alertContainer');

// initialize WASM module
init().then(() => {
    wasmLoaded = true;
    console.log('WASM module loaded successfully');
    updatePatchButtonState();
}).catch((error) => {
    console.error('Failed to load WASM module:', error);
});

// populate compatibility table
compatibilityTableData.forEach(item => {
    const row = document.createElement('tr');
    let titleCell = item.title;
    if (item.note) {
        titleCell += ` <span class="relative group ml-1 align-middle">
            <span class="absolute z-20 left-1/2 -translate-x-1/2 bottom-full mb-2 w-56 px-3 py-2 rounded bg-base-200 text-base-content text-xs shadow-lg opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-200 whitespace-normal">
                ${item.note}
            </span>
            <span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-base-200 text-base-content text-xs font-bold cursor-pointer">?</span>
        </span>`;
    }
    row.innerHTML = `
        <td>${titleCell}</td>
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

function crc32(buffer) {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let crc = i;
        for (let j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >>> 1) ^ 0xEDB88320;
            } else {
                crc >>>= 1;
            }
        }
        table[i] = crc >>> 0;
    }

    let crc = 0xFFFFFFFF;
    for (let byte of buffer) {
        const index = (crc ^ byte) & 0xFF;
        crc = (crc >>> 8) ^ table[index];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function handleFileSelect(event) {
    const selectedFile = event.target.files[0];
    statusDiv.textContent = `Selected file: ${selectedFile.name}`;
    fileBuffer = null; // reset file buffer
    alertContainer.innerHTML = ``; // clear previous alerts
    downloadLink.classList.add('hidden');
    updatePatchButtonState();

    const reader = new FileReader();
    reader.onload = function (event) {
        try {
            const arrayBuffer = event.target.result;
            const inputBytes = new Uint8Array(arrayBuffer);

            // calculate CRC32 and check compatibility
            const crc = crc32(inputBytes);
            const crcHex = crc.toString(16).padStart(8, '0');
            const compatible = compatibilityTableData.find(item => item.crc32 === crcHex);

            if (compatible) {
                showAlert(`Compatible file detected for \"${compatible.title}\"`, 'success');
            } else {
                showAlert('Warning: File is not listed as compatible', 'warning');
            }

            fileBuffer = inputBytes; // Store the valid file buffer
            updatePatchButtonState();
        } catch (error) {
            console.error(error);
            showAlert('Error: Unable to process the selected file', 'error');
        }
    };

    reader.readAsArrayBuffer(selectedFile);
}

function updatePatchButtonState() {
    patchButton.disabled = !(wasmLoaded && fileBuffer);
}

function showAlert(message, type) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} shadow-lg w-80`;

    const icon = type === 'success' 
        ? `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
           </svg>`
        : `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
           </svg>`;

    alert.innerHTML = `
        <div class="flex items-center">
            ${icon}
            <span class="ml-2">${message}</span>
        </div>
    `;

    alertContainer.appendChild(alert);

    setTimeout(() => alert.remove(), 5000); // auto-remove after 5 seconds
}

function patchFile() {
    if (!fileBuffer || !wasmLoaded) return;

    // reset status and alerts
    statusDiv.textContent = ``;
    alertContainer.innerHTML = ``;

    try {
        // patch the file buffer
        const outputBytes = patch(fileBuffer);

        // create a download link for the patched file
        const blob = new Blob([outputBytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);

        // pffer download as filename.nocd.ext
        const stem = fileInput.files[0].name.split('.')[0];
        const ext = fileInput.files[0].name.split('.').pop();
        const downloadName = `${stem}.nocd.${ext}`;

        downloadLink.href = url;
        downloadLink.download = downloadName;
        downloadLink.classList.remove('hidden');
    } catch (error) {
        console.error(error);
        showAlert('Error: Failed to patch the file', 'error');
    }
}
