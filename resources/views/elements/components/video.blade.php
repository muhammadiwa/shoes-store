<x-app-layout>
    <div class="space-y-8">
        <div>
            <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="card">
            <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                        <div class="card-title text-slate-900 dark:text-white">Video</div>
                    </div>
                </header>
                <div class="card-text h-full space-y-10">
                    <video class="w-full" id="player" playsinline="playsinline" controls="controls"
                        class="w-full"
                        id="player"
                        playsinline="playsinline"
                        controls="controls"
                        data-poster="https://vjs.zencdn.net/v/oceans.png">
                        <source src="https://vjs.zencdn.net/v/oceans.mp4" type="video/mp4">
                    </video>
                </div>
            </div>
        </div>
    </div>

    @push('scripts')
        @vite(['resources/js/plugins/plyr.min.js'])
        <script type="module">
            // Video Player
            const player = new Plyr("#player", {
                controls: [
                    "play-large",
                    "current-time",
                    "progress",
                    "mute",
                    "volume",
                    "pip",
                    "fullscreen",
                    "settings",
                ],
            });
        </script>
    @endpush
</x-app-layout>
