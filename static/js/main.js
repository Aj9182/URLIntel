// ============================================
// THEME LOGIC
// ============================================
const html = document.documentElement;
const savedTheme = localStorage.getItem("theme");

// 1. If user previously chose a theme, use it
if (savedTheme === "light") {
  html.classList.remove("dark");
} else if (savedTheme === "dark") {
  html.classList.add("dark");
} 
// 2. Otherwise, check the OS device preference
else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
  html.classList.add("dark");
  localStorage.setItem("theme", "dark");
} 
// 3. Fallback to light
else {
  html.classList.remove("dark");
  localStorage.setItem("theme", "light");
}

function toggleTheme() {
  html.classList.toggle("dark");

  if (html.classList.contains("dark")) {
    localStorage.setItem("theme", "dark");
  } else {
    localStorage.setItem("theme", "light");
  }

  // If there's a Chart in the page (admin dashboard), re-render it
  if (typeof createChart === "function") {
    createChart();
  }
}

// ============================================
// PARTICLE ANIMATION LOGIC
// ============================================
const canvas = document.getElementById("particle-network");

if (canvas) {
  const ctx = canvas.getContext("2d");

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  
  resizeCanvas();
  window.addEventListener("resize", resizeCanvas);

  let mouse = { x: null, y: null };
  window.addEventListener("mousemove", (e) => { mouse.x = e.x; mouse.y = e.y; });
  window.addEventListener("mouseleave", () => { mouse.x = null; mouse.y = null; });

  let particles = [];
  const count = 80;

  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.6,
      vy: (Math.random() - 0.5) * 0.6
    });
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const isDark = document.documentElement.classList.contains("dark");
    const particleColor = isDark ? "white" : "#111827";
    const lineColor = isDark ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.15)";

    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      // Mouse interaction
      if (mouse.x && mouse.y) {
        let dx = p.x - mouse.x;
        let dy = p.y - mouse.y;
        let dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 120 && dist !== 0) {
          let force = (120 - dist) / 120;
          p.x += (dx / dist) * force * 2;
          p.y += (dy / dist) * force * 2;

          // Glow effect
          ctx.beginPath();
          ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
          ctx.fillStyle = particleColor;
          ctx.shadowBlur = 15;
          ctx.shadowColor = particleColor;
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
      ctx.fillStyle = particleColor;
      ctx.fill();
    });

    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        let dx = particles[i].x - particles[j].x;
        let dy = particles[i].y - particles[j].y;
        let dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = lineColor;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }

  draw();
}
