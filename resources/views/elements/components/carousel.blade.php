<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Basic Example</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class=" slider basic-carousel owl-carousel">
                                <img class="w-full" src="images/all-img/c1.png" alt="image">
                                <img class="w-full" src="images/all-img/c2.png" alt="image">
                                <img class="w-full" src="images/all-img/c3.png" alt="image">
                                <img class="w-full" src="images/all-img/c4.png" alt="image">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">With Captions</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="slider basic-carousel width-caption owl-carousel">
                                <div class="relative">
                                    <img class="w-full" src="images/all-img/c1.png" alt="image">
                                    <div class="absolute w-full bottom-14 text-center">
                                        <h3 class="text-white font-Inter text-lg">Title</h3>
                                        <p class="text-white font-Inter text-sm">Lorem ipsum dolor sit amet.</p>
                                    </div>
                                </div>
                                <div class="relative">
                                    <img class="w-full" src="images/all-img/c2.png" alt="image">
                                    <div class="absolute w-full bottom-14 text-center">
                                        <h3 class="text-white font-Inter text-lg">Title</h3>
                                        <p class="text-white font-Inter text-sm">Lorem ipsum dolor sit amet.</p>
                                    </div>
                                </div>
                                <div class="relative">
                                    <img class="w-full" src="images/all-img/c3.png" alt="image">
                                    <div class="absolute w-full bottom-14 text-center">
                                        <h3 class="text-white font-Inter text-lg">Title</h3>
                                        <p class="text-white font-Inter text-sm">Lorem ipsum dolor sit amet.</p>
                                    </div>
                                </div>
                                <div class="relative">
                                    <img class="w-full" src="images/all-img/c3.png" alt="image">
                                    <div class="absolute w-full bottom-14 text-center">
                                        <h3 class="text-white font-Inter text-lg">Title</h3>
                                        <p class="text-white font-Inter text-sm">Lorem ipsum dolor sit amet.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Carousel Interval</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="slider carousel-interval owl-carousel">
                                <img class="w-full" src="images/all-img/c1.png" alt="image">
                                <img class="w-full" src="images/all-img/c2.png" alt="image">
                                <img class="w-full" src="images/all-img/c3.png" alt="image">
                                <img class="w-full" src="images/all-img/c4.png" alt="image">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Crossfade</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="slider carousel-crossfade owl-carousel">
                                <img class="w-full" src="images/all-img/c1.png" alt="image">
                                <img class="w-full" src="images/all-img/c2.png" alt="image">
                                <img class="w-full" src="images/all-img/c3.png" alt="image">
                                <img class="w-full" src="images/all-img/c4.png" alt="image">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    @push('scripts')
        @vite(['resources/js/plugins/owl.carousel.min.js'])
        <script type="module">
            // Basic Carousel
            $(".basic-carousel").owlCarousel({
                loop: true,
                nav: true,
                items: 1,
                lazyLoad: true,
                navText: [
                    '<iconify-icon icon="ic:round-arrow-back-ios"></iconify-icon>',
                    '<iconify-icon icon="ic:round-arrow-forward-ios"></iconify-icon>',
                ],
            });

            // Carousel Interval
            $(".carousel-interval").owlCarousel({
                autoplay: true,
                autoplayTimeout: 3000,
                autoplayHoverPause: true,
                lazyLoad: true,
                loop: true,
                nav: true,
                items: 1,
                navText: [
                    '<iconify-icon icon="ic:round-arrow-back-ios"></iconify-icon>',
                    '<iconify-icon icon="ic:round-arrow-forward-ios"></iconify-icon>',
                ],
            });

            //Carousel Crossfade
            $(".carousel-crossfade").owlCarousel({
                autoplay: true,
                autoplayTimeout: 3000,
                autoplayHoverPause: true,
                lazyLoad: true,
                loop: true,
                nav: true,
                items: 1,
                animateIn: "fadeIn",
                animateOut: "fadeOut",
                navText: [
                    '<iconify-icon icon="ic:round-arrow-back-ios"></iconify-icon>',
                    '<iconify-icon icon="ic:round-arrow-forward-ios"></iconify-icon>',
                ],
            });
        </script>
    @endpush
</x-app-layout>
