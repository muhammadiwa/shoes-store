<x-app-layout>
    <div class="space-y-8">

        <div class="mb-5">
            <ul class="m-0 p-0 list-none">
                <li class="inline-block relative top-[3px] text-base text-primary-500 font-Inter ">
                    <a href="index.html">
                        <iconify-icon icon="heroicons-outline:home"></iconify-icon>
                        <iconify-icon icon="heroicons-outline:chevron-right" class="relative text-slate-500 text-sm rtl:rotate-180"></iconify-icon>
                    </a>
                </li>
                <li class="inline-block relative text-sm text-primary-500 font-Inter "> Components
                    <iconify-icon icon="heroicons-outline:chevron-right" class="relative top-[3px] text-slate-500 rtl:rotate-180"></iconify-icon>
                </li>
                <li class="inline-block relative text-sm text-slate-500 font-Inter dark:text-white"> Pagination</li>
            </ul>
        </div>

        <div class="grid md:grid-cols-2 grid-cols-1 gap-5">
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Basic Pagination</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-10">
                        <ul class="list-none">
                            <li class="inline-block">
                                <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 relative top-[2px] pl-2">
                                    <iconify-icon icon="material-symbols:arrow-back-ios-rounded"></iconify-icon>
                                </a>
                            </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 p-active">
                                    1</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    2</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    3</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    4</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    5</a> </li>
                            <li class="inline-block">
                                <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 relative top-[2px]">
                                    <iconify-icon icon="material-symbols:arrow-forward-ios-rounded"></iconify-icon>
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Pagination With Background</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-10">
                        <ul class="list-none inline-block rounded bg-slate-100 dark:bg-slate-700 px-3 py-2 inli  dark:text-whitene-block">
                            <li class="inline-block">
                                <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 relative top-[2px]">
                                    <iconify-icon icon="material-symbols:arrow-back-ios-rounded"></iconify-icon>
                                </a>
                            </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100  text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 p-active">
                                    1</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    2</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    3</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    4</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    5</a> </li>
                            <li class="inline-block">
                                <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 relative top-[2px]">
                                    <iconify-icon icon="material-symbols:arrow-forward-ios-rounded"></iconify-icon>
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Pagination With Text</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-10 text-center">
                        <ul class="list-none">
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 text-slate-600 mr-5 ml-5 text-sm font-Inter font-medium transition-all
                                            duration-300 relative dark:text-white">
                                    Previous
                                  </a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 p-active">
                                    1</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    2</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    3</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    4</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                            dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                            duration-300 ">
                                    5</a> </li>
                            <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 text-slate-600 ml-3 text-sm font-Inter font-medium transition-all
                                            duration-300 relative dark:text-white">
                                    Next
                                  </a> </li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Advanced Pagination</div>
                        </div>
                    </header>
                    <div class="card-text h-full flex flex-wrap items-center justify-between">
                        <div class="flex items-center space-x-2 mb-2 sm:mb-0">
                            <select class="dataNumber borde bg-transparent !border-slate-400 dark:!border-slate-600 !pr-5 rounded-md" id="dataNumber">
                                <option value="0" disabled="disabled">Go</option>
                                <option value="1">1</option>
                                <option value="5">5</option>
                                <option value="10">10</option>
                            </select> <span>of 10 entries</span> </div>
                        <div>
                            <ul class="list-none">
                                <li class="inline-block">
                                    <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                duration-300 relative top-[2px] pl-2">
                                        <iconify-icon icon="material-symbols:arrow-back-ios-rounded"></iconify-icon>
                                    </a>
                                </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 text-slate-800
                                                dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                duration-300 p-active">
                                      1</a> </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                duration-300 ">
                                      2</a> </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                duration-300 ">
                                      3</a> </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                duration-300 ">
                                      4</a> </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                duration-300 ">
                                      5</a> </li>
                                <li class="inline-block">
                                    <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                dark:text-white rounded mx-[3px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                duration-300 relative top-[2px]">
                                        <iconify-icon icon="material-symbols:arrow-forward-ios-rounded"></iconify-icon>
                                    </a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card col-span-1 md:col-span-2 rounded-md bg-white dark:bg-slate-800 lg:h-full shadow-base">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Advanced Pagination With Page Selector</div>
                        </div>
                    </header>
                    <div class="card-text h-full flex flex-wrap items-center justify-between">
                        <div class="flex items-center space-x-2 mb-2 sm:mb-0">
                            <input type="text" class="w-9 h-9 rounded-md border !border-slate-300 text-center focus:!border-slate-300 focus:!outline-1 focus:!ring-transparent font-Inter
                                        font-medium text-sm bg-transparent dark:text-white dark:!border-slate-900" placeholder="0">
                            <button class="w-9 h-9 rounded-md border border-slate-300 bg-black-500 text-white font-Inter font-medium text-sm
                                        focus:!outline-transparent focus:!ring-transparent dark:border-slate-700"> Go</button>
                        </div>
                        <div>
                            <ul class="list-none">
                                <li class="inline-block">
                                    <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                    dark:text-white rounded mx-[2px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                    duration-300 relative top-[2px]">
                                        <iconify-icon icon="material-symbols:arrow-back-ios-rounded"></iconify-icon>
                                    </a>
                                </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 text-slate-800
                                                    dark:text-white rounded mx-[2px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                    duration-300 p-active">
                                      1</a> </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                    dark:text-white rounded mx-[2px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                    duration-300 ">
                                      2</a> </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                    dark:text-white rounded mx-[2px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                    duration-300 ">
                                      3</a> </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                    dark:text-white rounded mx-[2px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                    duration-300 ">
                                      4</a> </li>
                                <li class="inline-block"> <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                    dark:text-white rounded mx-[2px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                    duration-300 ">
                                      5</a> </li>
                                <li class="inline-block">
                                    <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                                    dark:text-white rounded mx-[2px] sm:mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                                    duration-300 relative top-[2px]">
                                        <iconify-icon icon="material-symbols:arrow-forward-ios-rounded"></iconify-icon>
                                    </a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
