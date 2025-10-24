// In your main script
const worker = new Worker('worker.js');

worker.onmessage = function(e) {
    // Handle the response from the worker (e.g., update UI)
    console.log('Received message from worker', e.data);
};

// Post data to worker (e.g., start streaming task)
worker.postMessage({ action: 'startStream', streamIP: '' });
// In worker.js
self.onmessage = function(e) {
    const { action, streamIP } = e.data;
    if (action === 'startStream') {
        // Perform heavy task here, like fetching data or processing
        // Do not block the UI thread
        self.postMessage('Stream started');
    }
};
