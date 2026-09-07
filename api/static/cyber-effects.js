/**
 * VulnEye Cyber Graphics & Animation Engine
 * Handles interactive cyber particle constellations, radar sweeps, sound synthesis, and theme state.
 */

(function () {
    'use strict';

    // ----------------------------------------------------
    // 1. Interactive Cyber Particle Constellation Canvas
    // ----------------------------------------------------
    class CyberCanvas {
        constructor() {
            this.canvas = document.getElementById('cyber-canvas');
            if (!this.canvas) {
                this.canvas = document.createElement('canvas');
                this.canvas.id = 'cyber-canvas';
                this.canvas.className = 'cyber-canvas';
                document.body.prepend(this.canvas);
            }
            this.ctx = this.canvas.getContext('2d');
            this.particles = [];
            this.mouse = { x: null, y: null, radius: 140 };
            this.particleCount = 55;
            this.maxDistance = 140;
            this.animationFrameId = null;

            this.init();
        }

        init() {
            this.resize();
            window.addEventListener('resize', () => this.resize());
            window.addEventListener('mousemove', (e) => {
                this.mouse.x = e.clientX;
                this.mouse.y = e.clientY;
            });
            window.addEventListener('mouseleave', () => {
                this.mouse.x = null;
                this.mouse.y = null;
            });

            this.createParticles();
            this.animate();
        }

        resize() {
            this.width = this.canvas.width = window.innerWidth;
            this.height = this.canvas.height = window.innerHeight;
            if (this.width < 768) {
                this.particleCount = 28;
                this.maxDistance = 90;
            } else {
                this.particleCount = 60;
                this.maxDistance = 140;
            }
        }

        createParticles() {
            this.particles = [];
            for (let i = 0; i < this.particleCount; i++) {
                this.particles.push({
                    x: Math.random() * this.width,
                    y: Math.random() * this.height,
                    vx: (Math.random() - 0.5) * 0.7,
                    vy: (Math.random() - 0.5) * 0.7,
                    radius: Math.random() * 2 + 1,
                    pulseSpeed: 0.02 + Math.random() * 0.03,
                    pulse: Math.random() * Math.PI,
                    isSpecial: Math.random() > 0.85
                });
            }
        }

        getColors() {
            const isDark = document.body.classList.contains('dark');
            return isDark
                ? {
                      node: 'rgba(0, 240, 255, 0.8)',
                      nodeSpecial: 'rgba(168, 85, 247, 0.9)',
                      line: 'rgba(0, 240, 255, ',
                      mouseLine: 'rgba(168, 85, 247, '
                  }
                : {
                      node: 'rgba(37, 99, 235, 0.7)',
                      nodeSpecial: 'rgba(124, 58, 237, 0.8)',
                      line: 'rgba(37, 99, 235, ',
                      mouseLine: 'rgba(124, 58, 237, '
                  };
        }

        animate() {
            this.ctx.clearRect(0, 0, this.width, this.height);
            const colors = this.getColors();

            // Update & draw particles
            for (let i = 0; i < this.particles.length; i++) {
                const p = this.particles[i];
                p.x += p.vx;
                p.y += p.vy;
                p.pulse += p.pulseSpeed;

                if (p.x < 0 || p.x > this.width) p.vx *= -1;
                if (p.y < 0 || p.y > this.height) p.vy *= -1;

                const currentRadius = p.radius + Math.sin(p.pulse) * 0.8;

                this.ctx.beginPath();
                this.ctx.arc(p.x, p.y, Math.max(0.5, currentRadius), 0, Math.PI * 2);
                this.ctx.fillStyle = p.isSpecial ? colors.nodeSpecial : colors.node;
                this.ctx.shadowBlur = p.isSpecial ? 12 : 6;
                this.ctx.shadowColor = p.isSpecial ? '#a855f7' : '#00f0ff';
                this.ctx.fill();
                this.ctx.shadowBlur = 0;

                // Connect particles to mouse
                if (this.mouse.x !== null && this.mouse.y !== null) {
                    const dxMouse = this.mouse.x - p.x;
                    const dyMouse = this.mouse.y - p.y;
                    const distMouse = Math.sqrt(dxMouse * dxMouse + dyMouse * dyMouse);

                    if (distMouse < this.mouse.radius) {
                        const alpha = (1 - distMouse / this.mouse.radius) * 0.5;
                        this.ctx.beginPath();
                        this.ctx.moveTo(p.x, p.y);
                        this.ctx.lineTo(this.mouse.x, this.mouse.y);
                        this.ctx.strokeStyle = colors.mouseLine + alpha + ')';
                        this.ctx.lineWidth = 1.2;
                        this.ctx.stroke();
                    }
                }

                // Connect particles to each other
                for (let j = i + 1; j < this.particles.length; j++) {
                    const p2 = this.particles[j];
                    const dx = p.x - p2.x;
                    const dy = p.y - p2.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < this.maxDistance) {
                        const alpha = (1 - dist / this.maxDistance) * 0.22;
                        this.ctx.beginPath();
                        this.ctx.moveTo(p.x, p.y);
                        this.ctx.lineTo(p2.x, p2.y);
                        this.ctx.strokeStyle = colors.line + alpha + ')';
                        this.ctx.lineWidth = 0.8;
                        this.ctx.stroke();
                    }
                }
            }

            this.animationFrameId = requestAnimationFrame(() => this.animate());
        }
    }

    // ----------------------------------------------------
    // 2. High-Tech Cyber Sound Synthesizer (Web Audio API)
    // ----------------------------------------------------
    class CyberSound {
        constructor() {
            const savedAudio = localStorage.getItem('vulneye_audio');
            // Default to Enabled (true)
            this.enabled = savedAudio === null ? true : savedAudio === 'true';
            this.audioCtx = null;
        }

        initContext() {
            if (!this.audioCtx && typeof window.AudioContext !== 'undefined') {
                const AudioContextClass = window.AudioContext || window.webkitAudioContext;
                this.audioCtx = new AudioContextClass();
            }
            if (this.audioCtx && this.audioCtx.state === 'suspended') {
                this.audioCtx.resume();
            }
            return this.audioCtx;
        }

        toggle() {
            const ctx = this.initContext();
            if (ctx && ctx.state === 'suspended') {
                ctx.resume();
            }
            this.enabled = !this.enabled;
            localStorage.setItem('vulneye_audio', this.enabled);
            
            if (this.enabled) {
                this.playToggle(true);
                this.showAudioToast('🔊 Cyber SFX: ENABLED');
            } else {
                this.playToggle(false);
                this.showAudioToast('🔇 Cyber SFX: MUTED');
            }
            return this.enabled;
        }

        showAudioToast(msg) {
            let toast = document.getElementById('vulneye-audio-toast');
            if (!toast) {
                toast = document.createElement('div');
                toast.id = 'vulneye-audio-toast';
                toast.className = 'cyber-audio-toast';
                document.body.appendChild(toast);
            }
            toast.textContent = msg;
            toast.classList.add('visible');
            clearTimeout(toast._timeout);
            toast._timeout = setTimeout(() => {
                toast.classList.remove('visible');
            }, 1800);
        }

        // Generic Tone Synthesizer with Attack-Decay Envelope and Audible Gain
        playTone(freq = 600, duration = 0.08, type = 'sine', vol = 0.25, endFreq = null) {
            if (!this.enabled) return;
            try {
                const ctx = this.initContext();
                if (!ctx) return;

                if (ctx.state === 'suspended') {
                    ctx.resume().then(() => this._executeTone(freq, duration, type, vol, endFreq));
                } else {
                    this._executeTone(freq, duration, type, vol, endFreq);
                }
            } catch (e) {}
        }

        _executeTone(freq, duration, type, vol, endFreq) {
            try {
                const now = this.audioCtx.currentTime;
                const osc = this.audioCtx.createOscillator();
                const gain = this.audioCtx.createGain();

                osc.type = type;
                osc.frequency.setValueAtTime(freq, now);
                if (endFreq) {
                    osc.frequency.exponentialRampToValueAtTime(Math.max(20, endFreq), now + duration);
                }

                // Attack-Decay Envelope
                gain.gain.setValueAtTime(0.001, now);
                gain.gain.linearRampToValueAtTime(vol, now + 0.012);
                gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);

                osc.connect(gain);
                gain.connect(this.audioCtx.destination);

                osc.start(now);
                osc.stop(now + duration + 0.02);
            } catch (e) {}
        }

        // 1. Futuristic Button Hover Chirp (Clearly Audible)
        playHover() {
            this.playTone(720, 0.06, 'sine', 0.18, 1100);
        }

        // 2. Crisp Futuristic Click
        playClick() {
            this.playTone(1200, 0.08, 'triangle', 0.28, 320);
        }

        // 3. Audio Toggle Sound (Ascending for ON, Descending for OFF)
        playToggle(isOn) {
            if (!this.enabled && isOn === undefined) return;
            try {
                const ctx = this.initContext();
                if (!ctx) return;
                
                const triggerChime = () => {
                    const now = this.audioCtx.currentTime;
                    if (isOn) {
                        // Ascending Power-Up 3-tone Chime
                        [587.33, 880, 1174.66].forEach((freq, idx) => {
                            const osc = this.audioCtx.createOscillator();
                            const gain = this.audioCtx.createGain();
                            osc.type = 'triangle';
                            osc.frequency.setValueAtTime(freq, now + idx * 0.06);
                            gain.gain.setValueAtTime(0.001, now + idx * 0.06);
                            gain.gain.linearRampToValueAtTime(0.24, now + idx * 0.06 + 0.015);
                            gain.gain.exponentialRampToValueAtTime(0.0001, now + idx * 0.06 + 0.14);
                            osc.connect(gain);
                            gain.connect(this.audioCtx.destination);
                            osc.start(now + idx * 0.06);
                            osc.stop(now + idx * 0.06 + 0.16);
                        });
                    } else {
                        // Descending Power-Down
                        this.playTone(950, 0.15, 'sawtooth', 0.2, 220);
                    }
                };

                if (ctx.state === 'suspended') {
                    ctx.resume().then(triggerChime);
                } else {
                    triggerChime();
                }
            } catch (e) {}
        }

        // 4. Modal / Dropdown Aperture Open/Close
        playModal(isOpen = true) {
            if (isOpen) {
                this.playTone(380, 0.1, 'triangle', 0.24, 1050);
            } else {
                this.playTone(950, 0.09, 'sine', 0.2, 320);
            }
        }

        // 5. Success Notification / Copy Chord
        playSuccess() {
            if (!this.enabled) return;
            try {
                const ctx = this.initContext();
                if (!ctx) return;
                
                const triggerSuccess = () => {
                    const now = this.audioCtx.currentTime;
                    // Rich 3-Tone Major Chord (C5 -> E5 -> G5)
                    [523.25, 659.25, 783.99].forEach((freq, i) => {
                        const osc = this.audioCtx.createOscillator();
                        const gain = this.audioCtx.createGain();
                        osc.type = 'triangle';
                        osc.frequency.setValueAtTime(freq, now + i * 0.06);
                        gain.gain.setValueAtTime(0.001, now + i * 0.06);
                        gain.gain.linearRampToValueAtTime(0.28, now + i * 0.06 + 0.015);
                        gain.gain.exponentialRampToValueAtTime(0.0001, now + i * 0.06 + 0.28);
                        osc.connect(gain);
                        gain.connect(this.audioCtx.destination);
                        osc.start(now + i * 0.06);
                        osc.stop(now + i * 0.06 + 0.3);
                    });
                };

                if (ctx.state === 'suspended') {
                    ctx.resume().then(triggerSuccess);
                } else {
                    triggerSuccess();
                }
            } catch (e) {}
        }

        // 6. Sonar / Radar Ping
        playScanPing() {
            if (!this.enabled) return;
            try {
                this.playTone(1500, 0.35, 'sine', 0.3, 350);
            } catch (e) {}
        }

        // 7. Data Stream / Keystroke Chirp
        playKeystroke() {
            this.playTone(1400 + Math.random() * 250, 0.035, 'triangle', 0.15, 800);
        }

        // Legacy compatibility
        playBeep(freq = 600, duration = 0.08, type = 'sine', vol = 0.2) {
            this.playTone(freq, duration, type, vol);
        }
    }

    // ----------------------------------------------------
    // 3. Global Theme Management & Init
    // ----------------------------------------------------
    const soundSynth = new CyberSound();
    let canvasInstance = null;

    window.toggleDark = function () {
        document.body.classList.toggle('dark');
        const isDark = document.body.classList.contains('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        updateThemeUI(isDark);
        if (isDark) {
            soundSynth.playTone(450, 0.08, 'triangle', 0.07, 950);
        } else {
            soundSynth.playTone(950, 0.08, 'triangle', 0.07, 450);
        }

        if (typeof window.updateChartsTheme === 'function') {
            window.updateChartsTheme(isDark);
        }
    };

    window.toggleAudio = function () {
        const state = soundSynth.toggle();
        const audioBtn = document.getElementById('audioToggleBtn');
        if (audioBtn) {
            audioBtn.innerHTML = state ? '🔊 <span>SFX On</span>' : '🔇 <span>SFX Off</span>';
            audioBtn.classList.toggle('active', state);
        }
    };

    function updateThemeUI(isDark) {
        const icon = document.getElementById('themeIcon');
        const text = document.getElementById('themeText');
        if (icon) icon.textContent = isDark ? '☀️' : '🌙';
        if (text) text.textContent = isDark ? 'Light' : 'Dark';
    }

    // Quick target chip filler helper
    window.setScanTarget = function (url) {
        soundSynth.initContext();
        const input = document.querySelector('input[name="url"]');
        if (input) {
            input.value = '';
            let index = 0;
            soundSynth.playClick();
            const typeInterval = setInterval(() => {
                if (index < url.length) {
                    input.value += url[index];
                    soundSynth.playKeystroke();
                    index++;
                } else {
                    clearInterval(typeInterval);
                    soundSynth.playSuccess();
                    input.focus();
                }
            }, 30);
        }
    };

    // Copy to clipboard helper
    window.copyToClipboard = function (text, btnElement) {
        soundSynth.initContext();
        navigator.clipboard.writeText(text).then(() => {
            soundSynth.playSuccess();
            if (btnElement) {
                const original = btnElement.innerHTML;
                btnElement.innerHTML = '✓ Copied!';
                btnElement.classList.add('copied');
                setTimeout(() => {
                    btnElement.innerHTML = original;
                    btnElement.classList.remove('copied');
                }, 2000);
            }
        });
    };

    // User Profile Dropdown Toggle
    window.toggleUserProfileMenu = function (e) {
        soundSynth.initContext();
        if (e) {
            if (e.stopPropagation) e.stopPropagation();
            if (e.stopImmediatePropagation) e.stopImmediatePropagation();
        }
        const menu = document.getElementById('userProfileMenu');
        const btn = document.getElementById('userProfileBtn');
        if (menu) {
            const isCurrentlyOpen = menu.classList.contains('show');
            if (isCurrentlyOpen) {
                menu.classList.remove('show');
                if (btn) btn.classList.remove('active');
                soundSynth.playModal(false);
            } else {
                menu.classList.add('show');
                if (btn) btn.classList.add('active');
                soundSynth.playModal(true);
            }
        }
    };

    // Global Click-Outside & Escape Handler to Close Dropdowns
    document.addEventListener('click', (e) => {
        const dropdown = document.getElementById('userProfileDropdown');
        const menu = document.getElementById('userProfileMenu');
        const btn = document.getElementById('userProfileBtn');
        if (menu && dropdown && !dropdown.contains(e.target)) {
            if (menu.classList.contains('show')) {
                menu.classList.remove('show');
                if (btn) btn.classList.remove('active');
                soundSynth.playModal(false);
            }
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const menu = document.getElementById('userProfileMenu');
            const btn = document.getElementById('userProfileBtn');
            if (menu && menu.classList.contains('show')) {
                menu.classList.remove('show');
                if (btn) btn.classList.remove('active');
                soundSynth.playModal(false);
            }
        }
    });

    // Interactive button audio binding & UI initialization
    document.addEventListener('DOMContentLoaded', () => {
        // Unlock Web Audio Context on first user interaction anywhere
        const unlockAudio = () => {
            soundSynth.initContext();
            document.removeEventListener('click', unlockAudio);
            document.removeEventListener('keydown', unlockAudio);
            document.removeEventListener('touchstart', unlockAudio);
        };
        document.addEventListener('click', unlockAudio, { once: true, passive: true });
        document.addEventListener('keydown', unlockAudio, { once: true, passive: true });
        document.addEventListener('touchstart', unlockAudio, { once: true, passive: true });

        // Theme initialization
        const savedTheme = localStorage.getItem('theme');
        const isDark = savedTheme ? savedTheme === 'dark' : true;
        if (isDark) {
            document.body.classList.add('dark');
            updateThemeUI(true);
        } else {
            document.body.classList.remove('dark');
            updateThemeUI(false);
        }

        // Initialize Audio toggle button visual state
        const audioBtn = document.getElementById('audioToggleBtn');
        if (audioBtn) {
            audioBtn.innerHTML = soundSynth.enabled ? '🔊 <span>SFX On</span>' : '🔇 <span>SFX Off</span>';
            audioBtn.classList.toggle('active', soundSynth.enabled);
        }

        // Initialize Cyber Canvas
        canvasInstance = new CyberCanvas();

        // 1. Global Hover Sound Listeners for All Interactive Elements
        document.addEventListener('mouseover', (e) => {
            const target = e.target.closest('button, a, .nav-link, .quick-chip, .tool-card, .pricing-card, .payment-tab-btn, .history-row, .faq-item, .chip-tag, input[type="submit"]');
            if (target && !target.dataset.sfxHoverBound) {
                target.dataset.sfxHoverBound = 'true';
                target.addEventListener('mouseenter', () => soundSynth.playHover());
            }
        });

        // 2. Global Click Sound for Action Elements
        document.addEventListener('click', (e) => {
            soundSynth.initContext();
            const clickable = e.target.closest('button:not(#audioToggleBtn), a:not(#audioToggleBtn), .quick-chip, .payment-tab-btn, .faq-item');
            if (clickable) {
                soundSynth.playClick();
            }
        });

        // 3. Keystroke sound on Search / Scan inputs
        const targetInput = document.querySelector('input[name="url"], input[type="text"]');
        if (targetInput) {
            targetInput.addEventListener('keydown', (e) => {
                if (e.key.length === 1 || e.key === 'Backspace' || e.key === 'Enter') {
                    soundSynth.playKeystroke();
                }
            });
        }
    });

    window.VulnEyeAudio = soundSynth;
})();
