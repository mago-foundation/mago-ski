// Copies the renderer's static files next to the compiled app.js.
import { copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const gui = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const from = path.join(gui, 'src', 'renderer');
const to = path.join(gui, 'dist', 'gui', 'src', 'renderer');
await mkdir(to, { recursive: true });
for (const file of ['index.html', 'styles.css']) await copyFile(path.join(from, file), path.join(to, file));
