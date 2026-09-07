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
    // 2. Sci-Fi Cyber Sound Synthesizer (Web Audio API)
    // ----------------------------------------------------
    class CyberSound {
        constructor() {
            this.enabled = localStorage.getItem('vulneye_audio') === 'true';
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
        }

        toggle() {
            this.enabled = !this.enabled;
            localStorage.setItem('vulneye_audio', this.enabled);
            if (this.enabled) {
                this.initContext();
                this.playBeep(880, 0.08, 'sine');
            }
            return this.enabled;
        }

        playBeep(freq = 600, duration = 0.05, type = 'sine', vol = 0.05) {
            if (!this.enabled) return;
            try {
                this.initContext();
                if (!this.audioCtx) return;

                const osc = this.audioCtx.createOscillator();
                const gain = this.audioCtx.createGain();

                osc.type = type;
                osc.frequency.setValueAtTime(freq, this.audioCtx.currentTime);
                osc.frequency.exponentialRampToValueAtTime(freq * 0.5, this.audioCtx.currentTime + duration);

                gain.gain.setValueAtTime(vol, this.audioCtx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.0001, this.audioCtx.currentTime + duration);

                osc.connect(gain);
                gain.connect(this.audioCtx.destination);

                osc.start();
                osc.stop(this.audioCtx.currentTime + duration);
            } catch (e) {
                // Ignore audio restriction errors
            }
        }

        playScanPing() {
            if (!this.enabled) return;
            try {
                this.initContext();
                if (!this.audioCtx) return;

                const now = this.audioCtx.currentTime;
                const osc = this.audioCtx.createOscillator();
                const gain = this.audioCtx.createGain();

                osc.type = 'triangle';
                osc.frequency.setValueAtTime(1200, now);
                osc.frequency.exponentialRampToValueAtTime(400, now + 0.25);

                gain.gain.setValueAtTime(0.08, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);

                osc.connect(gain);
                gain.connect(this.audioCtx.destination);

                osc.start(now);
                osc.stop(now + 0.25);
            } catch (e) {}
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
        soundSynth.playBeep(isDark ? 650 : 900, 0.06);

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
        const input = document.querySelector('input[name="url"]');
        if (input) {
            input.value = '';
            let index = 0;
            soundSynth.playBeep(750, 0.04);
            const typeInterval = setInterval(() => {
                if (index < url.length) {
                    input.value += url[index];
                    index++;
                } else {
                    clearInterval(typeInterval);
                    input.focus();
                }
            }, 25);
        }
    };

    // Copy to clipboard helper
    window.copyToClipboard = function (text, btnElement) {
        navigator.clipboard.writeText(text).then(() => {
            soundSynth.playBeep(1100, 0.08);
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

    // Interactive button audio binding
    document.addEventListener('DOMContentLoaded', () => {
        // Theme initialization
        const savedTheme = localStorage.getItem('theme');
        // Default to dark theme for high-tech cyber aesthetics unless explicitly set to light
        const isDark = savedTheme ? savedTheme === 'dark' : true;
        if (isDark) {
            document.body.classList.add('dark');
            updateThemeUI(true);
        } else {
            document.body.classList.remove('dark');
            updateThemeUI(false);
        }

        // Initialize Audio toggle state
        const audioBtn = document.getElementById('audioToggleBtn');
        if (audioBtn) {
            audioBtn.innerHTML = soundSynth.enabled ? '🔊 <span>SFX On</span>' : '🔇 <span>SFX Off</span>';
            audioBtn.classList.toggle('active', soundSynth.enabled);
        }

        // Initialize Canvas
        canvasInstance = new CyberCanvas();

        // Button hover sound listeners
        document.querySelectorAll('button, a.back-btn, a.google-btn, .quick-chip').forEach((el) => {
            el.addEventListener('mouseenter', () => {
                soundSynth.playBeep(520, 0.02, 'sine', 0.02);
            });
        });
    });

    window.VulnEyeAudio = soundSynth;
})();
