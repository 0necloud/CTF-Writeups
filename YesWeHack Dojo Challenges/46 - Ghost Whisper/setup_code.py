import os
os.chdir('tmp')
os.mkdir('templates')

os.environ["FLAG"] = flag

with open('templates/index.html', 'w') as f:
    f.write('''
<!DOCTYPE html>
<html lang="en">
  <head>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Averia+Sans+Libre:ital,wght@0,300;0,400;0,700;1,300;1,400;1,700&family=Changa:wght@200..800&family=Coiny&family=Finger+Paint&family=Jersey+15&family=Knewave&family=Nosifer&family=Schoolbell&family=Sour+Gummy:ital,wght@0,100..900;1,100..900&display=swap"
      rel="stylesheet"
    />
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <style>
      * {
        font-family: "Sour Gummy", sans-serif;
        font-optical-sizing: auto;
        font-weight: 400;
        font-style: normal;
        font-variation-settings: "wdth" 100;
      }
      /* Flicker / projection effect */
      @keyframes glow {
        0%,
        100% {
          text-shadow: 0 0 5px #0ff, 0 0 15px #0ff, 0 0 25px #0ff;
          opacity: 0.9;
        }
        50% {
          text-shadow: 0 0 10px #0ff, 0 0 30px #0ff, 0 0 50px #0ff;
          opacity: 1;
        }
      }
      @keyframes flicker {
        0%,
        19%,
        21%,
        23%,
        25%,
        54%,
        56%,
        100% {
          opacity: 1;
        }
        20%,
        24%,
        55% {
          opacity: 0.4;
        }
      }
      .projection-text {
        animation: glow 2s infinite alternate, flicker 6s infinite;
      }
      .projection-bg {
        background: radial-gradient(ellipse at center, #0a0f1f 0%, #000 100%);
      }
    </style>
  </head>
  <body class="projection-bg min-h-screen flex items-center justify-center">
    <img class="rotate-180 absolute w-full h-full bg-zoom opacity-20" src="https://static.vecteezy.com/ti/gratis-vektor/p1/16962601-laskigt-halloween-affisch-med-spindel-webb-gratis-vector.jpg">
    <nav class="absolute top-0 w-full">
      <div
        class="max-w-screen-xl flex flex-wrap items-center justify-between"
      >
        <ul class="px-4 font-medium flex mt-4 flex-row space-x-4">
          <li>
            <a
              href="#"
              class="block py-2 px-3 text-white hover:text-blue-300"
              aria-current="page"
              >Home</a
            >
          </li>
          <li>
            <a
              href="#"
              class="block py-2 px-3 text-white rounded-2xl bg-gray-800"
              >Chat</a
            >
          </li>
          <li>
            <a href="#" class="block py-2 px-3 text-white hover:text-blue-300">List</a>
          </li>
          <li>
            <a href="#" class="block py-2 px-3 text-white hover:text-blue-300">Club</a>
          </li>
          <li>
            <a href="#" class="block py-2 px-3 text-white hover:text-blue-300"
              >Profile</a
            >
          </li>
        </ul>
      </div>
    </nav>

    <div class="w-full max-w-3xl">
      <!-- Title bar with ghost -->
      <div class="flex items-center justify-between mb-4 px-12">
        <h1
          class="font-bold text-cyan-400 font-mono text-4xl tracking-widest"
        >
          Sp00ky Ghost Whisper
        </h1>
        <!-- Placeholder ghost image -->
        <img
          class="w-42 h-42 animate-pulse"
          src="https://static.vecteezy.com/system/resources/previews/050/769/345/non_2x/cute-ghost-with-a-knife-free-png.png"
          alt="Ghost"
        />
      </div>

      <label class="block mb-2 text-sm font-medium text-white"
        >Whisper to me...</label
      >
      <input
        type="text"
        class="bg-gray-900 border border-gray-700 text-gray-400 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5"
        placeholder="B0000oooo..." value="{{ msg }}"
      />
      <p class="my-2 text-sm text-gray-400">
        We'll share all your details. Read our
        <a href="#" class="font-medium text-blue-300 hover:underline"
          >None Privacy Policy</a
        >.
      </p>

      <!-- Projection box -->
      <div
        class="p-6 rounded-lg bg-black/40 border border-cyan-500/30 shadow-lg shadow-cyan-500/20"
      >
        <p
          class="text-cyan-400 font-mono text-sm md:text-base projection-text"
        >
{{ hextext }}
 </p
        >
      </div>
    </div>
  </body>
</html>
'''.strip())