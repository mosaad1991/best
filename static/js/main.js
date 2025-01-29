// الثوابت
const API_BASE_URL = 'https://githubproject-j9js.onrender.com';
const API_ENDPOINTS = {
    process: '/api/process',
    stream: '/api/stream',
    health: '/health',
    cancel: '/api/cancel'
};

// حالة التطبيق
let isProcessing = false;
let eventSource = null;

// التحقق من حالة الخادم
async function checkServerHealth() {
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.health}`);
        return response.ok;
    } catch (error) {
        console.error('Server health check failed:', error);
        return false;
    }
}

// إظهار/إخفاء عناصر واجهة المستخدم
const UI = {
    showLoading() {
        document.getElementById('loading').classList.remove('hidden');
    },
    hideLoading() {
        document.getElementById('loading').classList.add('hidden');
    },
    showResults() {
        document.getElementById('results').classList.remove('hidden');
        document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
    },
    hideResults() {
        document.getElementById('results').classList.add('hidden');
    },
    showError(message) {
        const errorDiv = document.getElementById('error');
        errorDiv.querySelector('.error-message').textContent = message;
        errorDiv.classList.remove('hidden');
        errorDiv.scrollIntoView({ behavior: 'smooth' });
    },
    hideError() {
        document.getElementById('error').classList.add('hidden');
    },
    togglePasswordVisibility(inputId) {
        const input = document.getElementById(inputId);
        const button = input.nextElementSibling;
        const type = input.type === 'password' ? 'text' : 'password';
        input.type = type;
        button.textContent = type === 'password' ? '👁️' : '🔒';
    },
    resetForm() {
        document.getElementById('videoForm').reset();
    },
    updateProgress(taskNumber, progress) {
        const progressElement = document.getElementById(`task${taskNumber}Progress`);
        if (progressElement) {
            progressElement.style.width = `${progress}%`;
            progressElement.textContent = `${Math.round(progress)}%`;
        }
    },
    updateTaskStatus(taskNumber, status) {
        const statusElement = document.getElementById(`task${taskNumber}Status`);
        if (statusElement) {
            statusElement.textContent = status;
            statusElement.className = `status-${status.toLowerCase()}`;
        }
    }
};

// معالجة وعرض النتائج
const Results = {
    taskResults: {},

    updateTask(taskNumber, result) {
        this.taskResults[`task${taskNumber}`] = result;
        this.displayTaskResult(taskNumber);
    },

    displayTaskResult(taskNumber) {
        const result = this.taskResults[`task${taskNumber}`];
        if (!result) return;

        const resultDiv = document.getElementById(`task${taskNumber}Result`);
        if (!resultDiv) return;

        let content = '';

        switch(taskNumber) {
            case 1: // المواضيع
                content = this.formatTopics(result.content);
                break;
            case 2: // تحليل الاتجاهات
                content = this.formatTrends(result.content);
                break;
            case 4: // النصوص
                content = this.formatScript(result.content);
                break;
            case 5: // SEO
                content = this.formatSEO(result.content);
                break;
            case 8: // الصوت
                if (result.content && result.content.audio_data) {
                    content = this.createAudioPlayer(result.content.audio_data);
                }
                break;
            case 11: // الصور
                if (result.content && result.content.scenes) {
                    content = this.formatImageScenes(result.content.scenes);
                }
                break;
            default:
                content = this.formatContent(result.content);
        }

        resultDiv.innerHTML = content;
        UI.showResults();
    },

    formatContent(content) {
        if (!content) return '';
        
        if (typeof content === 'object') {
            content = JSON.stringify(content, null, 2);
        }

        return content
            .replace(/\n/g, '<br>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" target="_blank">$1</a>');
    },

    formatTopics(topics) {
        if (!topics) return '';
        return `<ul class="list-disc list-inside space-y-2">
            ${topics.split('\n').map(topic => `<li>${topic}</li>`).join('')}
        </ul>`;
    },

    formatTrends(trends) {
        return this.formatContent(trends);
    },

    formatScript(script) {
        return `<div class="prose max-w-none">
            ${this.formatContent(script)}
        </div>`;
    },

    formatSEO(seo) {
        return `<div class="space-y-4">
            ${this.formatContent(seo)}
        </div>`;
    },

    createAudioPlayer(audioData) {
        const audioBlob = this.base64ToBlob(audioData, 'audio/mp3');
        const audioUrl = URL.createObjectURL(audioBlob);
        return `<audio controls class="w-full mt-4">
            <source src="${audioUrl}" type="audio/mp3">
            Your browser does not support the audio element.
        </audio>`;
    },

    formatImageScenes(scenes) {
        return scenes.map(scene => `
            <div class="scene-container mb-8">
                <h4 class="font-medium mb-2">Scene ${scene.scene_number}</h4>
                <p class="mb-2">${scene.scene_content}</p>
                <img src="${scene.images.display}" 
                     alt="Scene ${scene.scene_number}" 
                     class="rounded-lg shadow-lg max-w-full h-auto"
                     loading="lazy">
                <p class="text-sm text-gray-500 mt-2">
                    Timing: ${scene.timing.start.toFixed(1)}s - ${(scene.timing.start + scene.timing.duration).toFixed(1)}s
                </p>
            </div>
        `).join('');
    },

    base64ToBlob(base64, type = 'audio/mp3') {
        const byteCharacters = atob(base64);
        const byteArrays = [];
        
        for (let offset = 0; offset < byteCharacters.length; offset += 1024) {
            const slice = byteCharacters.slice(offset, offset + 1024);
            const byteNumbers = new Array(slice.length);
            
            for (let i = 0; i < slice.length; i++) {
                byteNumbers[i] = slice.charCodeAt(i);
            }
            
            byteArrays.push(new Uint8Array(byteNumbers));
        }
        
        return new Blob(byteArrays, { type });
    }
};

// معالجة التحديثات المباشرة
function setupEventSource() {
    if (eventSource) {
        eventSource.close();
    }

    eventSource = new EventSource(`${API_BASE_URL}${API_ENDPOINTS.stream}`);

    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        
        switch(data.type) {
            case 'task_complete':
                Results.updateTask(data.task, data.result);
                UI.updateTaskStatus(data.task, 'completed');
                break;
            case 'progress':
                UI.updateProgress(data.task, data.progress);
                break;
            case 'error':
                UI.showError(data.message);
                break;
        }
    };

    eventSource.onerror = function(error) {
        console.error('EventSource failed:', error);
        eventSource.close();
    };
}

// معالجة الطلبات
const API = {
    async processVideo(data) {
        try {
            const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.process}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `Server error: ${response.status}`);
            }

            const result = await response.json();
            return result;

        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    async cancelTask(taskId) {
        try {
            const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.cancel}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ task_id: taskId })
            });

            if (!response.ok) {
                throw new Error('Failed to cancel task');
            }

            return await response.json();
        } catch (error) {
            console.error('Cancel task error:', error);
            throw error;
        }
    }
};

// معالج النموذج
document.getElementById('videoForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    if (isProcessing) {
        return;
    }

    UI.hideResults();
    UI.hideError();
    UI.showLoading();
    isProcessing = true;

    try {
        const isServerHealthy = await checkServerHealth();
        if (!isServerHealthy) {
            throw new Error('Server is currently unavailable. Please try again later.');
        }

        const data = {
            api_keys: {
                google_api_key: document.getElementById('googleApiKey').value,
                eleven_labs_api_key: document.getElementById('elevenLabsApiKey').value,
                eleven_labs_voice_id: document.getElementById('elevenLabsVoiceId').value
            },
            topic: document.getElementById('topic').value
        };

        setupEventSource();
        const result = await API.processVideo(data);

        if (result.status === 'success' && result.data && result.data.results) {
            Object.entries(result.data.results).forEach(([taskKey, taskResult]) => {
                const taskNumber = parseInt(taskKey.replace('task', ''));
                Results.updateTask(taskNumber, taskResult);
            });
        } else {
            throw new Error('Invalid response format');
        }

    } catch (error) {
        UI.showError(error.message);
        if (eventSource) {
            eventSource.close();
        }
    } finally {
        UI.hideLoading();
        isProcessing = false;
    }
});

// معالجة أزرار إظهار/إخفاء كلمة المرور
document.querySelectorAll('.password-toggle').forEach(button => {
    button.addEventListener('click', function() {
        UI.togglePasswordVisibility(this.dataset.target);
    });
});

// تنظيف الأخطاء عند تغيير المدخلات
document.querySelectorAll('input, textarea').forEach(input => {
    input.addEventListener('input', () => UI.hideError());
});