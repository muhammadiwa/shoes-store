@php

    $category = [
        [
            'cta' => 'Graphic Designer (214) ',
        ],
        [
            'cta' => 'Engineering Jobs (514) ',
        ],
        [
            'cta' => 'Mainframe Jobs (554)',
        ],
        [
            'cta' => 'Legal Jobs (457)',
        ],
        [
            'cta' => 'IT Jobs (1254) ',
        ],
        [
            'cta' => 'R&D Jobs (554) ',
        ],
        [
            'cta' => 'Government Jobs (350) ',
        ],
        [
            'cta' => 'PSL Jobs (221)',
        ],
    ];

    $tags = [
        [
            'title' => 'Business',
            'link' => '#',
        ],
        [
            'title' => 'Consulting',
            'link' => '#',
        ],
        [
            'title' => 'Photographic',
            'link' => '#',
        ],
        [
            'title' => 'Investment',
            'link' => '#',
        ],
        [
            'title' => 'Camera',
            'link' => '#',
        ],
        [
            'title' => 'Assurance',
            'link' => '#',
        ],
        [
            'title' => 'Secutity',
            'link' => '#',
        ],
    ];
@endphp
<x-app-layout>
    <div class="space-y-8">
        <div>
            <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="lg:flex flex-wrap blog-posts lg:space-x-5 space-y-5 lg:space-y-0 rtl:space-x-reverse">
            <div class="flex-none">
                <div class="lg:max-w-[360px]">
                    <div class="card">
                        <!-- START: Blog Sidebar -->
                        <div class="card-body pb-6">
                            <div class="space-y-5 divide-y divide-slate-100 dark:divide-slate-700">
                                <!-- Search Bar -->
                                <div class="p-6 border-b border-slate-100">
                                    <div class="flex items-stretch inputGroup  has-append  ">
                                        <div class="flex-1">
                                            <div class="relative fromGroup ">
                                                <input type="text"
                                                    class="input-group-control block w-full focus:outline-none py-2 "
                                                    placeholder="Search....">
                                                <div
                                                    class="flex text-xl absolute ltr:right-[14px] rtl:left-[14px] top-1/2 -translate-y-1/2  space-x-1 rtl:space-x-reverse">
                                                </div>
                                            </div>
                                        </div>
                                        <div class="flex-none input-group-addon right">
                                            <div class="input-group-text  h-full append-slot">
                                                <button type="button"
                                                    class=" btn inline-flex justify-center btn-dark dark:bg-slate-600">
                                                    <span class="flex items-center">
                                                        <span class=" text-[20px] ">
                                                            <svg xmlns="http://www.w3.org/2000/svg"
                                                                xmlns:xlink="http://www.w3.org/1999/xlink"
                                                                aria-hidden="true" role="img"
                                                                class="iconify iconify--heroicons-outline"
                                                                width="1em" height="1em" viewBox="0 0 24 24">
                                                                <path fill="none" stroke="currentColor"
                                                                    stroke-linecap="round" stroke-linejoin="round"
                                                                    stroke-width="2"
                                                                    d="m21 21l-6-6m2-5a7 7 0 1 1-14 0a7 7 0 0 1 14 0Z">
                                                                </path>
                                                            </svg>
                                                        </span>
                                                    </span>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <!-- START: BLog List -->
                            <div class="py-4 px-6">
                                <h4 class="text-slate-600 dark:text-slate-300 text-xl font-medium mb-4">
                                    Latest Blogs Post
                                </h4>
                                <ul class="list-item space-y-4">
                                    <li>
                                        <div class="flex space-x-4 rtl:space-x-reverse">
                                            <div class="flex-none">
                                                <div class="h-20 w-20">
                                                    <img src="images/post/t-3.png" alt=""
                                                        class="block w-full h-full rounded">
                                                </div>
                                            </div>
                                            <div class="flex-1 flex flex-col">
                                                <h4 class="text-sm text-slate-600 font-regular leading-5 mb-4">
                                                    <a href="#">
                                                        Lorem ipsum dolor sit amet consectetur adipiscing
                                                    </a>
                                                    .
                                                </h4>
                                                <span class="text-xs text-slate-400">
                                                    <a href="#">Oct 09, 2021</a>
                                                </span>
                                            </div>
                                        </div>
                                    </li>
                                    <li>
                                        <div class="flex space-x-4 rtl:space-x-reverse">
                                            <div class="flex-none">
                                                <div class="h-20 w-20">
                                                    <img src="images/post/t-3.png" alt=""
                                                        class="block w-full h-full rounded">
                                                </div>
                                            </div>
                                            <div class="flex-1 flex flex-col">
                                                <h4 class="text-sm text-slate-600 font-regular leading-5 mb-4">
                                                    <a href="#">
                                                        Lorem ipsum dolor sit amet consectetur adipiscing
                                                    </a>
                                                    .
                                                </h4>
                                                <span class="text-xs text-slate-400">
                                                    <a href="#">Oct 09, 2021</a>
                                                </span>
                                            </div>
                                        </div>
                                    </li>
                                    <li>
                                        <div class="flex space-x-4 rtl:space-x-reverse">
                                            <div class="flex-none">
                                                <div class="h-20 w-20">
                                                    <img src="images/post/t-3.png" alt=""
                                                        class="block w-full h-full rounded">
                                                </div>
                                            </div>
                                            <div class="flex-1 flex flex-col">
                                                <h4 class="text-sm text-slate-600 font-regular leading-5 mb-4">
                                                    <a href="#">
                                                        Lorem ipsum dolor sit amet consectetur adipiscing
                                                    </a>
                                                    .
                                                </h4>
                                                <span class="text-xs text-slate-400">
                                                    <a href="#">Oct 09, 2021</a>
                                                </span>
                                            </div>
                                        </div>
                                    </li>
                                </ul>
                            </div>
                            <!-- END: BLog List -->

                            <!-- START: Blog Category -->
                            <div class="py-4 px-6 border-t border-slate-100">
                                <h4 class="text-slate-600 dark:text-slate-300 text-xl font-medium mb-4">
                                    Category
                                </h4>
                                <ul class="list-item space-y-6">
                                    @foreach ($category as $item)
                                        <li>
                                            <a href="#"
                                                class="flex space-x-1 items-start leading-[1] text-sm text-slate-500 dark:text-slate-300 hover:text-slate-900 transition
                                                    duration-150 rtl:space-x-reverse">
                                                <span class="text-sm">
                                                    <iconify-icon icon="heroicons:chevron-right-solid"></iconify-icon>
                                                </span>
                                                <span>{{ $item['cta'] }}</span>
                                            </a>
                                        </li>
                                    @endforeach
                                </ul>
                            </div>
                            <!-- END: Blog Category -->

                            <!-- START: Tags -->
                            <div class="py-4 px-6 border-t border-slate-100">
                                <h4 class="text-slate-600 dark:text-slate-300 text-xl font-medium mb-4">
                                    Popular tags
                                </h4>
                                <ul class="flex flex-wrap">
                                    @foreach ($tags as $item)
                                        <li class="mr-2 mb-2">
                                            <a href={{ $item['link'] }}
                                                class="text-xs font-normal text-slate-600 bg-slate-100 dark:bg-slate-600 dark:text-slate-300 py-1 px-3 rounded-full hover:bg-slate-900 hover:text-white transition duration-150">
                                                <span>{{ $item['title'] }}</span>
                                            </a>
                                        </li>
                                    @endforeach
                                </ul>
                            </div>
                            <!-- END: Tags -->

                            <!-- START: Newsletter Area -->
                            <div class="mx-6 bg-slate-900 dark:bg-slate-900 text-white rounded-xl p-6 space-y-4">
                                <h4 class="text-xl font-medium text-white">
                                    Subscribe to our blog
                                </h4>
                                <div class="text-sm">
                                    Lorem ipsum dolor sit amet, consectet ur adipiscing elit.
                                </div>
                                <form action="#" class="space-y-4">
                                    <input
                                        type="text"
                                        placeholder="Enter your email"
                                        class="form-control py-2 bg-transparent border-secondary-500 text-white placeholder:text-slate-400">
                                    <button type="submit" class="btn btn-light btn-sm w-full">
                                        Subscribe
                                    </button>
                                </form>
                            </div>
                            <!-- END: Newsletter Area -->
                        </div>
                        <!-- END: Blog Sidebar -->
                    </div>
                </div>
            </div>

            <div class="flex-1">
                <div class="grid xl:grid-cols-2 grid-cols-1 gap-5">
                    <div class="xl:col-span-2 col-span-1">
                        <div class="card">
                            <div class="card-body p-6">
                                <div class=" h-[248px] w-full mb-6 ">
                                    <img src="images/all-img/post-1.png" alt="" class=" w-full h-full  object-cover">
                                </div>
                                <div class="flex justify-between mb-4">
                                    <a href="#" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal">
                                        <span>
                                            <iconify-icon icon="heroicons-outline:calendar" class="text-slate-400 dark:text-slate-400 ltr:mr-2 rtl:ml-2 text-lg"></iconify-icon>
                                        </span>
                                        <span>
                                            10/02/2021</span>
                                    </a>
                                    <div class="flex space-x-4 rtl:space-x-reverse">
                                        <a href="#">
                                            <span class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal">
                                                <iconify-icon icon="heroicons-outline:chat" class="text-slate-400 dark:text-slate-400 ltr:mr-2 rtl:ml-2 text-lg"></iconify-icon> 3
                                            </span>
                                        </a>
                                        <a href="#">
                                            <span class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal">
                                                <iconify-icon icon="heroicons-outline:share" class="text-slate-400 dark:text-slate-400 ltr:mr-2 rtl:ml-2 text-lg"></iconify-icon> 4
                                            </span>
                                        </a>
                                    </div>
                                </div>
                                <h5 class="card-title text-slate-900">
                                    <a href="blog-details.html">
                                        At Healthcare you will be treated by caring
                                    </a>
                                </h5>
                                <div class="card-text dark:text-slate-300 mt-4 space-y-4">
                                    <p>
                                        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna
                                        aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip.Lorem ipsum dolor sit amet,
                                        consectetur adipiscing eli.
                                    </p>
                                    <button class="btn btn-outline-dark">Read more</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div class=" h-[248px] w-full mb-6 ">
                            <img src="images/all-img/post-1.png" alt="" class=" w-full h-full  object-cover">
                        </div>
                        <div class="px-6 pb-6">
                            <div class="flex justify-between mb-4">
                                <div>
                                    <h5 class="card-title text-slate-900">
                                        <a href="#">Lorem ipsum</a>
                                    </h5>
                                </div>
                                <a href="#" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal">
                                    <span>
                                        <iconify-icon icon="heroicons-outline:calendar" class="text-slate-400 dark:text-slate-400 ltr:mr-2 rtl:ml-2 text-lg"></iconify-icon>
                                    </span>
                                    <span>
                                        10/02/2021</span>
                                </a>
                            </div>
                            <div class="card-text dark:text-slate-300 mt-4">
                                <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
                                <div class="mt-4 space-x-4 rtl:space-x-reverse">
                                    <a href="#" class="btn-a">
                                        Learn more
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div class=" h-[248px] w-full  ">
                            <img src="images/all-img/post-1.png" alt="" class=" w-full h-full  object-cover">
                        </div>
                        <div class="p-6">
                            <div class="flex justify-between mb-4">
                                <div>
                                    <h5 class="card-title text-slate-900">
                                        <a href="#">Lorem ipsum</a>
                                    </h5>
                                </div>
                                <a href="#" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal">
                                    <span>
                                        <iconify-icon icon="heroicons-outline:calendar" class="text-slate-400 dark:text-slate-400 ltr:mr-2 rtl:ml-2 text-lg"></iconify-icon>
                                    </span>
                                    <span>
                                        10/02/2021</span>
                                </a>
                            </div>
                            <div class="card-text dark:text-slate-300 mt-4">
                                <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
                                <div class="mt-4 space-x-4 rtl:space-x-reverse">
                                    <a href="#" class="btn-a">
                                        Learn more
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div class=" h-[248px] w-full mb-6 ">
                            <img src="images/all-img/post-1.png" alt="" class=" w-full h-full  object-cover">
                        </div>
                        <div class="px-6 pb-6">
                            <div class="flex justify-between mb-4">
                                <div>
                                    <h5 class="card-title text-slate-900">
                                        <a href="#">Lorem ipsum</a>
                                    </h5>
                                </div>
                                <a href="#" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal">
                                    <span>
                                        <iconify-icon icon="heroicons-outline:calendar" class="text-slate-400 dark:text-slate-400 ltr:mr-2 rtl:ml-2 text-lg"></iconify-icon>
                                    </span>
                                    <span>
                                        10/02/2021</span>
                                </a>
                            </div>
                            <div class="card-text dark:text-slate-300 mt-4">
                                <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
                                <div class="mt-4 space-x-4 rtl:space-x-reverse">
                                    <a href="#" class="btn-a">
                                        Learn more
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div class=" h-[248px] w-full  ">
                            <img src="images/all-img/post-1.png" alt="" class=" w-full h-full  object-cover">
                        </div>
                        <div class="p-6">
                            <div class="flex justify-between mb-4">
                                <div>
                                    <h5 class="card-title text-slate-900">
                                        <a href="#">Lorem ipsum</a>
                                    </h5>
                                </div>
                                <a href="#" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal">
                                    <span>
                                        <iconify-icon icon="heroicons-outline:calendar" class="text-slate-400 dark:text-slate-400 ltr:mr-2 rtl:ml-2 text-lg"></iconify-icon>
                                    </span>
                                    <span>
                                        10/02/2021</span>
                                </a>
                            </div>
                            <div class="card-text dark:text-slate-300 mt-4">
                                <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
                                <div class="mt-4 space-x-4 rtl:space-x-reverse">
                                    <a href="#" class="btn-a">
                                        Learn more
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>


        </div>

    </div>


    </div>
</x-app-layout>
