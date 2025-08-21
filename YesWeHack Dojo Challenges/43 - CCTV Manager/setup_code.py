import os
os.chdir('tmp')
os.mkdir('templates')

os.environ["FLAG"] = flag

with open('templates/index.html', 'w') as f:
    f.write('''
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
  </head>
  <body class="text-white">
    <div class="flex w-full h-full items-center justify-center min-h-screen">
      <div
        class="absolute border-solid border-2 border-blue-500 items-center justify-center m-10 border bg-[#d4d0c8] rounded-sm"
      >
        <div
          class="title-bar flex items-center justify-between p-2 h-8 text-white text-sm font-bold inset-shadow-sm inset-shadow-blue-300"
        >
          <span>CCTV manager (v1.3.37)</span>
          <div class="flex gap-1">
            <button
              class="cursor-pointer bg-blue-500 border-solid border-1 border-white rounded-md inset-shadow-sm inset-shadow-blue-300"
            >
              <svg
                class="w-6 h-6 text-gray-800 dark:text-white"
                aria-hidden="true"
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                height="24"
                fill="none"
                viewBox="0 0 24 24"
              >
                <path
                  stroke="currentColor"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M5 9h4m0 0V5m0 4L4 4m15 5h-4m0 0V5m0 4 5-5M5 15h4m0 0v4m0-4-5 5m15-5h-4m0 0v4m0-4 5 5"
                />
              </svg>
            </button>
            <button
              class="cursor-pointer bg-blue-500 border-solid border-1 border-white rounded-md inset-shadow-sm inset-shadow-white"
            >
              <svg
                class="w-6 h-6 text-gray-800 dark:text-white"
                aria-hidden="true"
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                height="24"
                fill="none"
                viewBox="0 0 24 24"
              >
                <path
                  stroke="currentColor"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M3 11.5h13m-13 0V18a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1v-6.5m-13 0V9a1 1 0 0 1 1-1h11a1 1 0 0 1 1 1v2.5M9 5h11a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1h-1"
                />
              </svg>
            </button>

            <button
              class="cursor-pointer bg-red-500 border-solid border-1 border-white rounded-md inset-shadow-sm inset-shadow-white"
            >
              <svg
                class="w-6 h-6 text-gray-800 dark:text-white"
                aria-hidden="true"
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                height="24"
                fill="none"
                viewBox="0 0 24 24"
              >
                <path
                  stroke="currentColor"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M6 18 17.94 6M18 18 6.06 6"
                />
              </svg>
            </button>
          </div>
        </div>

        <div class="flex flex-col p-4 text-sm text-black">
          <span>Camera Id: 1<b>{{ model }}</b></span>
          <img
            class="bg-cover no-repeat w-[450px] h-[200px]"
            src="https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExdW93OHg2YWs3c3l2azBmbm9qZjVpbzJxc3psaWkzNzZhMGR2cnNzZSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3o7btTODQcZhN6eLQs/giphy.gif"
          />
          <div class="flex mt-2 gap-2">
            <button
              class="active:border-blue-500 cursor-pointer rounded-md border-solid border-1 inset-shadow-sm inset-shadow-white px-3 py-1"
            >
              On/Off
            </button>

            <button
              class="active:border-blue-500 cursor-pointer rounded-md border-solid border-1 inset-shadow-sm inset-shadow-white px-3 py-1"
            >
              Upload firmware
            </button>

            <button
              class="active:border-blue-500 cursor-pointer rounded-md border-solid border-1 inset-shadow-sm inset-shadow-white px-3 py-1"
            >
              Next camera
            </button>
          </div>
        </div>
      </div>
    </div>
    <div
      class="title-bar p-2 absolute bottom-0 w-full h-12 border-solid border-2 border-blue-300 inset-shadow-sm inset-shadow-blue-300"
    >
      <div class="flex gap-2">
        <button
          class="px-2 p-1 flex bg-green-700 gap-2 justify-center items-center active:border-blue-500 cursor-pointer rounded-md border-solid border-1 inset-shadow-sm inset-shadow-green-500"
        >
          <img
            class="w-6 h-auto no-repeat bg-cover"
            src="https://api.iconify.design/devicon:linux.svg?color=%23888888"
          />
          <span class="font-bold text-white">START</span>
        </button>
        <button class="cursor-pointer h-8 w-8 rounded-md no-repeat bg-white bg-cover bg-[url('https://api.iconify.design/ion:terminal.svg?color=%23000')]">
        </button>
      </div>
    </div>

    {% if access %}
    <img
      class="absolute bottom-0 right-0 px-4 py-6"
      src="https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExa3pzcTZxaXlmYTJ3OXdyaDV6cXJsNHdjeXk2a3A4djNwZ3lzZGRudiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3ohzdZRsT35ffgyYjC/giphy.gif"
    />
    {% else %}
    <div
      class="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 border-solid border-2 border-blue-500 items-center justify-center bg-[#d4d0c8] rounded-sm"
    >
      <div
        class="title-bar flex items-center justify-between p-2 h-8 text-white text-sm font-bold inset-shadow-sm inset-shadow-blue-300"
      >
        <span>Error</span>
        <div class="flex gap-1">
          <button
            class="cursor-pointer bg-red-500 border-solid border-1 border-white rounded-md inset-shadow-sm inset-shadow-white"
          >
            <svg
              class="w-6 h-6 text-gray-800 dark:text-white"
              aria-hidden="true"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              fill="none"
              viewBox="0 0 24 24"
            >
              <path
                stroke="currentColor"
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M6 18 17.94 6M18 18 6.06 6"
              />
            </svg>
          </button>
        </div>
      </div>

      <div class="flex flex p-4 gap-2 items-center justify-center text-sm text-black">
        <img class="w-6 h-6" src="https://api.iconify.design/emojione:warning.svg?color=%23888888">
        <span>Unauthorized (invalid token)</span>
      </div>
    </div>

    {% endif %}

    <style>
      @import url("https://fonts.googleapis.com/css2?family=Anta&family=Indie+Flower&family=League+Spartan:wght@100..900&family=Madimi+One&family=Nabla&family=Sunflower:wght@300&display=swap");
      body {
        background-image: url("https://static.vecteezy.com/ti/gratis-foton/p1/35821535-ai-genererad-en-gron-falt-pa-solnedgang-topografisk-realism-uhd-bild-bergig-vyer-gratis-fotona.jpg");
        background-repeat: no-repeat;
        background-position: center;
        background-size: cover;
        font-family: "League Spartan", sans-serif;
        font-optical-sizing: auto;
        font-weight: 400;
        font-style: normal;
      }
      .title-bar {
        background: linear-gradient(to right, #0154e3, #215092);
      }
    </style>
  </body>
</html>
   '''.strip())