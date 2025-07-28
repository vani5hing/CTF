***Notes***
You will need libsdl2! It should be installable from your package manager (apt/pacman/yum/etc.)
If animations are too slow, use the -anim-ms option to reduce frame delay

Jumpio has made it to the Heap Hopper's castle for their final confrontation.
Unfortunately, the dastardly Hopper seems to be invulnerable!
Can you help Jumpio destroy the Hopper and rescue the Princess Pomegranite?

This is an old school Rogue type game:
- All game objects are rendered as text on a grid of tiles.
- Movement and actions are turn-based. The total number of turns taken is shown at the top of the window.
- Despite appearing larger, the Heap Hopper and the Columns in the arena are still 1x1.

USAGE:
    villain-client [OPTION]... TTF_PATH SERVER_IP SERVER_PORT

DESCRIPTION:
    TTF_PATH
        path to a TTF font for displaying game objects

    SERVER_IP
        IP address of the server to connect to

    SERVER_PORT
        Port of the server to connnect to

    -cpx 
        Cell X pixels, default 24

    -cpy
        Cell Y pixels, default 32

    -ttf-pt
        Font render size, default 24

    -anim-ms
        Delay (in milliseconds) between rendered frames, default 16

CONTROLS:
Press W A X D to move in 4 directions.

Press S to stand still and pass a few turns worth of time.

While standing on the Heap Hopper's tail, press G to grab him.
Press G repeatedly after grabbing to charge up Jumpio's throw.

While grabbing the Heap Hopper, press Q W E A D Z X C to throw him in 8 directions.
The more you charge before throwing, the more damage the throw will do.

Columns can be destroyed by throwing the Heap Hopper at them.
