<x-app-layout>
    <div class="space-y-8">
        <div class="flex justify-between flex-wrap items-center mb-6">
            <h4 class="font-medium lg:text-2xl text-xl capitalize text-slate-900 inline-block ltr:pr-4 rtl:pl-4 mb-3 sm:mb-0">Ecommerce</h4>
            <div class="flex sm:space-x-4 space-x-2 sm:justify-end items-center rtl:space-x-reverse">
                <button class="btn inline-flex justify-center bg-white text-slate-700 dark:bg-slate-700 !font-normal dark:text-white ">
                    <span class="flex items-center">
                        <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2 font-light" icon="heroicons-outline:calendar"></iconify-icon>
                        <span>Weekly</span>
                    </span>
                </button>
                <button class="btn inline-flex justify-center bg-white text-slate-700 dark:bg-slate-700 !font-normal dark:text-white ">
                    <span class="flex items-center">
                        <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2 font-light" icon="heroicons-outline:filter"></iconify-icon>
                        <span>Select Date</span>
                    </span>
                </button>
            </div>
        </div>

        <div class="space-y-5">
            <div class="card ">
                <div class="card-header">
                    <h4 class="card-title">Basic Map</h4>
                </div>
                <div class="card-body p-6">
                    <div id="map" class=" w-full h-[300px]"></div>
                </div>
            </div>
            <div class="card ">
                <div class="card-header">
                    <h4 class="card-title">Leaflet Marker, Circle & Polygon Map</h4>
                </div>
                <div class="card-body p-6">
                    <div id="map2" class=" w-full h-[300px]"></div>
                </div>
            </div>
            <div class="card ">
                <div class="card-header">
                    <h4 class="card-title">Leaflet GeoJSON Map</h4>
                </div>
                <div class="card-body p-6">
                    <div id="map3" class=" w-full h-[300px]"></div>
                </div>
            </div>
            <div class="card ">
                <div class="card-header">
                    <h4 class="card-title">Vectore Map</h4>
                </div>
                <div class="card-body p-6">
                    <div id="world-map" class=" w-full h-[300px]"></div>
                </div>
            </div>
        </div>
    </div>

    @push('scripts')
        @vite(['resources/js/plugins/jquery-jvectormap-2.0.5.min.js'])
        @vite(['resources/js/plugins/jquery-jvectormap-world-mill-en.js'])
        @vite(['resources/js/custom/map-active.js'])
        <script type="module">
            // Basic Map
            if (document.getElementById("map") || document.getElementById("map2")) {
                // map active
                var position = [47.31322, -1.319482];
                var map = L.map("map").setView(position, 8);

                L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
                    attribution:
                        '&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors',
                    maxZoom: 18,
                }).addTo(map);

                L.marker(position)
                    .addTo(map)
                    .bindPopup(
                        '<div class="">A pretty CSS3 popup. <br /> Easily customizable.</div>'
                    )
                    .openPopup();
                // marker map
                var circleRadius = 4500;
                var polygonCoords = [
                    [47.2263299, -1.6222],
                    [47.21024000000001, -1.6270065],
                    [47.1969447, -1.6136169],
                    [47.18527929999999, -1.6143036],
                    [47.1794457, -1.6098404],
                    [47.1775788, -1.5985107],
                    [47.1676598, -1.5753365],
                    [47.1593731, -1.5521622],
                    [47.1593731, -1.5319061],
                    [47.1722111, -1.5143967],
                    [47.1960115, -1.4841843],
                    [47.2095404, -1.4848709],
                    [47.2291277, -1.4683914],
                    [47.2533687, -1.5116501],
                    [47.2577961, -1.5531921],
                    [47.26828069, -1.5621185],
                    [47.2657179, -1.589241],
                    [47.2589612, -1.6204834],
                    [47.237287, -1.6266632],
                    [47.2263299, -1.6222],
                ];
                var map2 = L.map("map2").setView(position, 10);
                L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
                    attribution:
                        '&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors',
                }).addTo(map2);
                L.marker(position).addTo(map2);
                L.circle(position, {
                    radius: circleRadius,
                }).addTo(map2);
                L.polygon(polygonCoords).addTo(map2);
            }

            // vector map init
            $("#world-map").vectorMap({
                map: "world_mill_en",
                normalizeFunction: "polynomial",
                hoverOpacity: 0.7,
                hoverColor: false,

                regionStyle: {
                    initial: { fill: "#8092FF" },
                    hover: { fill: "#4669fa", "fill-opacity": 1 },
                },

                backgroundColor: "transparent",
            });

        </script>
    @endpush
</x-app-layout>
