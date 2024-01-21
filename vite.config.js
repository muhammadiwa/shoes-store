import { defineConfig } from "vite";
import laravel from "laravel-vite-plugin";

export default defineConfig({
    plugins: [
        laravel({
            input: [
                "resources/css/app.scss",
                "resources/js/custom/store.js",
                "resources/js/plugins/jquery-jvectormap-2.0.5.min.js",
                "resources/js/plugins/jquery-jvectormap-world-mill-en.js",
                "resources/js/custom/chart-active.js",
                "resources/js/main.js",
                "resources/js/app.js",
            ],
            refresh: true,
        }),
    ],
});
