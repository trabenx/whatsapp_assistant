// static/js/upload.js
document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('upload-form');
    const fileInput = document.getElementById('file-input');
    const progressBarContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const statusMessages = document.getElementById('status-messages');

    uploadForm.addEventListener('submit', (e) => {
        e.preventDefault(); // Prevent the default form submission

        const file = fileInput.files[0];
        if (!file) {
            statusMessages.innerHTML = '<p class="error">Please select a file to upload.</p>';
            return;
        }

        // Reset and show progress bar
        progressBar.style.width = '0%';
        progressBar.textContent = '0%';
        progressBarContainer.style.display = 'block';
        statusMessages.innerHTML = '';

        const formData = new FormData();
        formData.append('file', file);

        const xhr = new XMLHttpRequest();

        // Listen for progress events
        xhr.upload.addEventListener('progress', (event) => {
            if (event.lengthComputable) {
                const percentComplete = Math.round((event.loaded / event.total) * 100);
                progressBar.style.width = percentComplete + '%';
                progressBar.textContent = percentComplete + '%';
            }
        });

        // Listen for completion
        xhr.addEventListener('load', () => {
            if (xhr.status === 200) {
                const response = JSON.parse(xhr.responseText);
                statusMessages.innerHTML = `<p class="success">${response.message}</p>`;
                progressBar.textContent = 'Done!';
                progressBar.classList.add('progress-bar-success');
            } else {
                const response = JSON.parse(xhr.responseText);
                statusMessages.innerHTML = `<p class="error">Upload failed: ${response.error || 'Server error'}</p>`;
                progressBar.classList.add('progress-bar-error');
            }
            // Reset form after a short delay
            setTimeout(() => {
                uploadForm.reset();
                progressBarContainer.style.display = 'none';
                progressBar.classList.remove('progress-bar-success', 'progress-bar-error');
            }, 3000);
        });

        // Listen for errors
        xhr.addEventListener('error', () => {
            statusMessages.innerHTML = '<p class="error">An error occurred during the upload. Please try again.</p>';
            progressBar.style.width = '100%';
            progressBar.textContent = 'Error!';
            progressBar.classList.add('progress-bar-error');
        });
        
        // Open and send the request
        xhr.open('POST', '/upload', true);
        xhr.send(formData);
    });
});