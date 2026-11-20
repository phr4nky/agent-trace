import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { App } from './app/app';

// Dark mode follows the operating system (SwipyUI switches on the `syui-dark` class).
const dark = window.matchMedia('(prefers-color-scheme: dark)');
document.documentElement.classList.toggle('syui-dark', dark.matches);
dark.addEventListener('change', (e) => document.documentElement.classList.toggle('syui-dark', e.matches));

bootstrapApplication(App, appConfig).catch((err) => console.error(err));
