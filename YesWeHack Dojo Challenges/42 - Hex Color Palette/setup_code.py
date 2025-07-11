import os

os.chdir("/tmp/")
os.makedirs("templates", exist_ok=True)
os.makedirs("xml", exist_ok=True)

with open("flag.txt", "w") as f:
    f.write(flag)

with open("xml/sample.xml", 'w') as f:
    f.write('''
<!DOCTYPE colors [
    <!ELEMENT colors (color*)>
    <!ELEMENT color (#PCDATA)>
]>
<colors>
    <color>#FF5733</color>
    <color>#1E3A8A</color>
    <color>#2ECC71</color>
    <color>#F1C40F</color>
    <color>#8E44AD</color>
    <color>#2C3E50</color>
    <color>#FFC0CB</color>
    <color>#00FFFF</color>
</colors>
''')

with open("xml/config.dtd", 'w') as f:
    f.write('''
<!ENTITY % dtd "<!ELEMENT config (#PCDATA)>">
%config_hex;
''')

with open("templates/index.tpl", "w") as f:
    f.write("""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');

        :root {
            --text-color: #E0E0E0;
            --highlight: #32a852;
            --shadow: rgba(0, 0, 0, 0.6);
            --navbar-bg: rgba(22, 22, 22, 0.1);
            --border-color: #444;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
        }

        body {
            background: #0a0a0a;
            color: var(--text-color);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            padding: 20px;
            position: relative;
        }

        #particles-js {
            position: absolute;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            z-index: -1;
        }

        .navbar {
            width: 100%;
            background: var(--navbar-bg);
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            box-shadow: 0px 4px 15px var(--shadow);
            position: absolute;
            top: 0;
            backdrop-filter: blur(5px);
        }

        .navbar .logo {
            font-size: 24px;
            font-weight: 800;
            color: var(--highlight);
        }

        .navbar .menu {
            display: flex;
            gap: 20px;
            align-items: center;
        }

        .navbar .menu a {
            color: var(--text-color);
            text-decoration: none;
            font-weight: 600;
            padding: 10px 15px;
            transition: 0.3s;
            border-radius: 8px;
            text-align: center;
        }

        .navbar .menu a:hover {
            background: var(--highlight);
            color: #fff;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .user-info img {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            border: 2px solid var(--highlight);
            object-fit: cover;
            vertical-align: middle;
        }

        .user-info span {
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
        }

        .content {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-grow: 1;
            text-align: center;
        }

        h2 {
            color: var(--highlight);
            font-weight: 800;
            margin-bottom: 20px;
        }

        .palette {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 12px;
            padding: 20px;
        }

        .color-box {
            width: 60px;
            height: 60px;
            border-radius: 10px;
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 14px;
            font-weight: 600;
            color: #FFF;
            text-shadow: 1px 1px 5px rgba(0, 0, 0, 0.5);
            border: 2px solid var(--border-color);
            transition: transform 0.2s ease-in-out;
        }

        .color-box:hover {
            transform: scale(1.1);
            box-shadow: 0px 0px 15px var(--highlight);
        }
    </style>
</head>
<body>
    <div id="particles-js"></div>
    <div class="navbar">
        <div class="logo">Hex Color Palette</div>
        <div class="menu">
            <a href="#">Dashboard</a>
            <a href="#">Settings</a>
            <a href="#">Help</a>
        </div>
        <div class="user-info">
            <img src="https://cdn-yeswehack.com/user/avatar/default_image" style="margin-top: 2px;">
            <span>FullStack HTML Dev</span>
        </div>
    </div>

    <div class="content">
        <h2>Extracted Color Palette</h2>
        <p class="debug">{{ output }}</p>
        <div class="palette">
            {% if colors %}
                {% for color in colors %}
                    <div class="color-box" style="background: {{ color }};">{{ color }}</div>
                {% endfor %}
            {% else %}
                <p class="debug">No colors detected.</p>
            {% endif %}
        </div>
    </div>

    <script>
        particlesJS("particles-js", {
            particles: {
                number: { value: 100 },
                color: { value: "#32a852" },
                shape: { type: "circle" },
                opacity: { value: 0.7 },
                size: { value: 3 },
                move: { speed: 4 },
                line_linked: { enable: true, color: "#32a852" },
            },
            interactivity: {
                detect_on: "canvas",
                events: {
                    onhover: { enable: true, mode: "repulse" },
                    onclick: { enable: true, mode: "push" },
                },
                modes: {
                    repulse: { distance: 100, duration: 0.4 },
                    push: { particles_nb: 4 },
                }
            }
        });
    </script>
</body>
</html>
""")