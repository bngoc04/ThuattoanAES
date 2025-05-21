document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const fileUpload = document.getElementById('fileUpload');
    const fileInput = document.getElementById('fileInput');
    const fileInfo = document.getElementById('fileInfo');
    const keyInput = document.getElementById('keyInput');
    const keyToggle = document.getElementById('keyToggle');
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const successAlert = document.getElementById('successAlert');
    const errorAlert = document.getElementById('errorAlert');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const statusText = document.getElementById('statusText');
    const autoDownload = document.getElementById('autoDownload');
    const removeMetadata = document.getElementById('removeMetadata');

    let selectedFile = null;
    let isProcessing = false;

    // Event Listeners
    fileUpload.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);
    keyToggle.addEventListener('click', toggleKeyVisibility);
    encryptBtn.addEventListener('click', () => processFile(true));
    decryptBtn.addEventListener('click', () => processFile(false));

    // Drag and Drop functionality
    fileUpload.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileUpload.style.borderColor = '#4361ee';
        fileUpload.style.backgroundColor = 'rgba(67, 97, 238, 0.1)';
    });

    fileUpload.addEventListener('dragleave', () => {
        fileUpload.style.borderColor = '#ccc';
        fileUpload.style.backgroundColor = 'transparent';
    });

    fileUpload.addEventListener('drop', (e) => {
        e.preventDefault();
        fileUpload.style.borderColor = '#ccc';
        fileUpload.style.backgroundColor = 'transparent';

        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            handleFileSelect();
        }
    });

    // Functions
    function handleFileSelect() {
        if (fileInput.files.length > 0) {
            selectedFile = fileInput.files[0];
            fileInfo.textContent = `${selectedFile.name} (${formatFileSize(selectedFile.size)})`;
            clearAlerts();
        }
    }

    function toggleKeyVisibility() {
        const icon = keyToggle.querySelector('i');
        if (keyInput.type === 'password') {
            keyInput.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            keyInput.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }

    async function processFile(isEncrypt) {
        // Validate inputs
        if (!selectedFile) {
            showError('Vui lòng chọn file trước khi tiếp tục');
            return;
        }
        
        if (!keyInput.value.trim()) {
            showError('Vui lòng nhập mật khẩu');
            return;
        }
        
        if (isProcessing) return;
        isProcessing = true;
        
        try {
            showProgress();
            clearAlerts();
            
            const key = deriveKey(keyInput.value.trim());
            const fileData = await readFileAsArrayBuffer(selectedFile);
            
            let result;
            if (isEncrypt) {
                statusText.textContent = 'Đang mã hóa file...';
                result = await encryptData(fileData, key);
            } else {
                statusText.textContent = 'Đang giải mã file...';
                result = await decryptData(fileData, key);
            }
            
            updateProgress(100);
            
            const extension = isEncrypt ? '.encrypted' : '.decrypted';
            const fileName = selectedFile.name + extension;
            
            if (autoDownload.checked) {
                downloadFile(result, fileName);
            }
            
            showSuccess(`File đã được ${isEncrypt ? 'mã hóa' : 'giải mã'} thành công!`);
        } catch (error) {
            console.error(error);
            showError(`Lỗi khi ${isEncrypt ? 'mã hóa' : 'giải mã'}: ${error.message}`);
        } finally {
            hideProgress();
            isProcessing = false;
        }
    }

    function deriveKey(password) {
        const salt = CryptoJS.lib.WordArray.random(128 / 8);
        const keySize = 256 / 32;
        const iterations = 10000;
        
        const key = CryptoJS.PBKDF2(password, salt, {
            keySize: keySize,
            iterations: iterations
        });
        
        return { key: key, salt: salt };
    }

    function readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(new Error('Lỗi đọc file'));
            reader.readAsArrayBuffer(file);
        });
    }

    async function encryptData(data, keyObj) {
        return new Promise((resolve) => {
            const wordArray = CryptoJS.lib.WordArray.create(data);
            const iv = CryptoJS.lib.WordArray.random(128 / 8);
            const encrypted = CryptoJS.AES.encrypt(wordArray, keyObj.key, {
                iv: iv,
                padding: CryptoJS.pad.Pkcs7,
                mode: CryptoJS.mode.CBC
            });
            const result = CryptoJS.lib.WordArray.create()
                .concat(keyObj.salt)
                .concat(iv)
                .concat(encrypted.ciphertext);
            
            resolve(wordArrayToUint8Array(result));
        });
    }

    async function decryptData(data, keyObj) {
        return new Promise((resolve, reject) => {
            try {
                const wordArray = CryptoJS.lib.WordArray.create(data);
                const salt = CryptoJS.lib.WordArray.create(wordArray.words.slice(0, 4));
                const iv = CryptoJS.lib.WordArray.create(wordArray.words.slice(4, 8));
                const ciphertext = CryptoJS.lib.WordArray.create(wordArray.words.slice(8));

                const key = CryptoJS.PBKDF2(keyInput.value.trim(), salt, {
                    keySize: 256 / 32,
                    iterations: 10000
                });

                const decrypted = CryptoJS.AES.decrypt(
                    { ciphertext: ciphertext },
                    key,
                    {
                        iv: iv,
                        padding: CryptoJS.pad.Pkcs7,
                        mode: CryptoJS.mode.CBC
                    }
                );

                resolve(wordArrayToUint8Array(decrypted));
            } catch (e) {
                reject(new Error('Khóa không đúng hoặc file đã bị hỏng'));
            }
        });
    }

    function wordArrayToUint8Array(wordArray) {
        const len = wordArray.words.length * 4;
        const u8Array = new Uint8Array(len);
        let offset = 0;
        
        for (let i = 0; i < wordArray.words.length; i++) {
            const word = wordArray.words[i];
            u8Array[offset++] = (word >> 24) & 0xff;
            u8Array[offset++] = (word >> 16) & 0xff;
            u8Array[offset++] = (word >> 8) & 0xff;
            u8Array[offset++] = word & 0xff;
        }
        
        return u8Array;
    }

    function downloadFile(data, fileName) {
        const blob = new Blob([data], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        setTimeout(() => {
            URL.revokeObjectURL(url);
        }, 100);
    }

    function showProgress() {
        progressContainer.style.display = 'block';
        progressBar.style.width = '0%';
    }

    function updateProgress(percent) {
        progressBar.style.width = `${percent}%`;
    }

    function hideProgress() {
        progressContainer.style.display = 'none';
    }

    function showSuccess(message) {
        successAlert.textContent = message;
        successAlert.style.display = 'block';
        errorAlert.style.display = 'none';
    }

    function showError(message) {
        errorAlert.textContent = message;
        errorAlert.style.display = 'block';
        successAlert.style.display = 'none';
    }

    function clearAlerts() {
        successAlert.style.display = 'none';
        errorAlert.style.display = 'none';
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
});