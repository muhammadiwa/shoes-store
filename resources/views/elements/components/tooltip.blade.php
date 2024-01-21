<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <!-- BEGIN: Tooltip Position -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Tooltip Position</div>
                        </div>
                    </header>
                    <div class="card-text h-full">
                        <p class="font-Inter font-normal text-base text-slate-600 mb-6 leading-6">Available options for positioning: <span class="py-1 px-2 bg-slate-200 rounded-md text-slate-900">top, top-start, top-end, bottom, bottom-start, bottom-end, left, left-start, left-end, right, right-start, right-end</span> </p>
                        <div class="space-y-2">
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-dark mr-3">Tooltip On Top</button>
                            <button class="toolTip onRight btn inline-flex justify-center btn-outline-dark mr-3">Tooltip On Right</button>
                            <button class="toolTip onBottom btn inline-flex justify-center btn-outline-dark mr-3">Tooltip On Bottom</button>
                            <button class="toolTip onLeft btn inline-flex justify-center btn-outline-dark mr-3">Tooltip On Left</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Tooltip Position -->
            <!-- BEGIN: Theme Tooltip -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Theme Style</div>
                        </div>
                    </header>
                    <div class="card-text h-full">
                        <div class="space-y-2">
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-primary mr-3" data-tippy-content="primary tooltip!" data-tippy-theme="primary">primary</button>
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-secondary mr-3" data-tippy-content="secondary tooltip!" data-tippy-theme="secondary">secondary</button>
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-info mr-3" data-tippy-content="info tooltip!" data-tippy-theme="info">info</button>
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-success mr-3" data-tippy-content="success tooltip!" data-tippy-theme="success">success</button>
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-warning mr-3" data-tippy-content="warning tooltip!" data-tippy-theme="warning">warning</button>
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-danger mr-3" data-tippy-content="danger tooltip!" data-tippy-theme="danger">danger</button>
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-dark mr-3" data-tippy-content="dark tooltip!" data-tippy-theme="dark">dark</button>
                            <button class="toolTip onTop btn inline-flex justify-center btn-outline-light mr-3" data-tippy-content="light tooltip!" data-tippy-theme="light">light</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Theme Tooltip -->
            <!-- BEGIN: Tooltip Animation -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Animations</div>
                        </div>
                    </header>
                    <div class="card-text h-full">
                        <p class="font-Inter font-normal text-base text-slate-600 mb-6 leading-6">Available Animations: <span class="py-1 px-2 bg-slate-200 rounded-md text-slate-900 text-sm">scale, scale-subtl, scale-extreme, perspective-extrem, perspective-subtle, perspective, shift-away-extreme shift-away-subtle, shift-away.css, shift-toward-extreme,shift-toward-subtle, shift-toward.</span> </p>
                        <div class="space-y-2">
                            <button class="shift-Away btn inline-flex justify-center btn-outline-dark mr-3" data-tippy-content="shift-Away" data-tippy-theme="dark">shift-Away</button>
                            <button class="shift-Toward btn inline-flex justify-center btn-outline-dark mr-3" data-tippy-content="shift-Toward" data-tippy-theme="dark">shift-Toward</button>
                            <button class="scale btn inline-flex justify-center btn-outline-dark mr-3" data-tippy-content="scale" data-tippy-theme="dark">scale</button>
                            <button class="perspective btn inline-flex justify-center btn-outline-dark mr-3" data-tippy-content="perspective" data-tippy-theme="dark">perspective</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Tooltip Animation -->
            <!-- BEGIN: Triger Tooltip -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Triggers</div>
                        </div>
                    </header>
                    <div class="card-text space-y-2 h-full">
                        <button class="shift-Toward btn inline-flex justify-center btn-outline-dark mr-3" data-tippy-content="Mouse Enter" data-tippy-theme="dark">Mouse Enter</button>
                        <button class="onClickTooltip btn inline-flex justify-center btn-outline-dark mr-3" data-tippy-content="On Click" data-tippy-theme="dark">On Click</button>
                    </div>
                </div>
            </div>
            <!-- END: Triger Tooltip -->
        </div>
    </div>
    @push('scripts')
        <script type="module">
            // Tooltip and Popover
            tippy(".onTop", {
                content: "Tooltip On Top!",
                placement: "top",
            });
            tippy(".onRight", {
                content: "Tooltip On Right!",
                placement: "right",
            });
            tippy(".onBottom", {
                content: "Tooltip On Bottom!",
                placement: "bottom",
            });
            tippy(".onLeft", {
                content: "Tooltip On Left!",
                placement: "left",
            });

            // ToolTip Animations
            tippy(".scale", {
                placement: "top",
                animation: "scale",
            });
            tippy(".shift-Away", {
                placement: "top",
                animation: "shift-away",
            });
            tippy(".shift-Toward", {
                placement: "top",
                animation: "shift-toward",
            });
            tippy(".perspective", {
                placement: "top",
                animation: "perspective",
            });

            tippy(".onClickTooltip", {
                placement: "top",
                animation: "shift-away",
                trigger: "click",
            });
        </script>
    @endpush
</x-app-layout>
