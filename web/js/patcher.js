import init, { patch } from "/wasm/noviy_nocd.js";

let wasmLoaded = false;
let selectedFile = null;

// DOM elements
const fileInput = document.getElementById('fileInput');
const patchButton = document.getElementById('patchButton');
const statusDiv = document.getElementById('status');
const downloadLink = document.getElementById('downloadLink');

// initialize WASM module
init().then(() => {
    wasmLoaded = true;
    console.log("WASM module loaded successfully");
    updatePatchButtonState();
});

// event listeners
fileInput.addEventListener('change', handleFileSelect);
patchButton.addEventListener('click', patchFile);

console.log = function (message) {
    statusDiv.textContent += message + '\n';
}

function handleFileSelect(event) {
    selectedFile = event.target.files[0];
    updatePatchButtonState();
}

function updatePatchButtonState() {
    patchButton.disabled = !(wasmLoaded && selectedFile);
}

function patchFile() {
    if (!selectedFile || !wasmLoaded) return;

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
