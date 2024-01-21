<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-6">
            <div class="grid xl:grid-cols-3 md:grid-cols-2 grid-cols-1 gap-5">
                <div class="card rounded-md bg-white dark:bg-slate-800 lg:h-full  shadow-base">
                    <div class="card-body flex flex-col p-6 active">
                        <header class="flex mb-5 items-center">
                            <div class="flex-1">
                                <div class="card-title font-Inter text-slate-900 dark:text-white">Card title</div>
                                <div class="card-subtitle font-Inter">This is a subtitle</div>
                            </div>
                        </header>
                        <div class="image-box mb-6"> <img src="/images/all-img/card-1.png" alt="" class="block w-full h-full object-cover rounded-md"> </div>
                        <div class="card-text h-full menu-open">
                            <p>Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut .</p>
                            <div class="mt-4 space-x-4 rtl:space-x-reverse"> <a href="card.html" class="underline btn-link active">Learn more</a> <a href="card.html" class="underline btn-link active">Another link</a> </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base active"> <img src="/images/all-img/card-2.png" alt="" class="block w-full h-full object-cover rounded-t-md">
                        <div class="items-center p-6 menu-open">
                            <h3 class="card-title text-slate-900 dark:text-white mb-1">Card title</h3>
                            <h6 class="card-subtitle mb-4">This is a subtitle</h6>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut.</p>
                            <div class="mt-4 space-x-4 rtl:space-x-reverse"> <a href="card.html" class="underline btn-link active">Learn more</a> <a href="card.html" class="underline btn-link active">Another link</a> </div>
                        </div>
                    </div>
                </div>
                <div class="rounded-md overlay bg-no-repeat bg-center bg-cover card" style="background-image: url('/images/all-img/card-3.png');">
                    <div class="card-body h-full flex flex-col justify-center p-6 active">
                        <div class="card-text flex flex-col justify-between h-full menu-open">
                            <h3 class="card-title font-Inter text-white">Card title</h3>
                            <div class="my-8 md:my-0">
                                <h5 class="card-subtitle text-white mb-3">This is a subtitle</h5>
                                <p class="text-white card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut.</p>
                            </div>
                            <div> <a href="card.html" class="btn inline-flex justify-center bg-white dark:bg-slate-800 dark:text-slate-300 text-slate-800 active">Learn more</a> </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="grid xl:grid-cols-4 md:grid-cols-2 grid-cols-1 gap-5">
                <div class="card">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base"> <img src="/images/all-img/card-4.png" alt="image" class="block w-full h-full object-cover rounded-t-md">
                        <div class="items-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white mb-3">Sales Automation</h3>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut.</p>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base">
                        <div class="items-center text-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white mb-3">Sales Automation</h3>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut.</p>
                        </div> <img src="/images/all-img/card-5.png" alt="image" class="block w-full h-full object-cover rounded-t-md"> </div>
                </div>
                <div class="card">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base"> <img src="/images/all-img/card-6.png" alt="image" class="block w-full h-full object-cover rounded-t-md">
                        <div class="items-center text-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white mb-3">Sales Automation</h3>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut.</p>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body rounded-md bg-[#E5F9FF] dark:bg-slate-700 shadow-base">
                        <div class="items-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white mb-3">API Questions</h3>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut.</p>
                        </div> <img src="/images/all-img/card-7.png" alt="image" class="block w-full h-full object-cover rounded-t-md"> </div>
                </div>
                <div class="card active">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base menu-open">
                        <div class="items-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white">Sales Automation</h3>
                            <p class="card-text my-5">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p> <a href="card.html" class="underline btn-link active">Learn more</a> </div>
                    </div>
                </div>
                <div class="card dark active">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base menu-open">
                        <div class="items-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white">Sales Automation</h3>
                            <p class="card-text my-5">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p> <a href="card.html" class="underline btn-link active">Learn more</a> </div>
                    </div>
                </div>
                <div class="card active">
                    <div class="card-body rounded-md bg-[#EDFFE5] dark:bg-slate-800 shadow-base menu-open">
                        <div class="items-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white">Sales Automation</h3>
                            <p class="card-text my-5">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p> <a href="card.html" class="underline btn-link active">Learn more</a> </div>
                    </div>
                </div>
                <div class="card active">
                    <div class="card-body rounded-md bg-[#E5F9FF] dark:bg-slate-800 shadow-base menu-open">
                        <div class="items-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white">Sales Automation</h3>
                            <p class="card-text my-5">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p> <a href="card.html" class="underline btn-link active">Learn more</a> </div>
                    </div>
                </div>
            </div>
            <div class="grid xl:grid-cols-3 md:grid-cols-2 grid-cols-1 gap-5">
                <div class="card active">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base menu-open">
                        <div class="items-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white">Sales Automation</h3>
                            <p class="card-text my-7">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p> <a href="card.html" class="btn inline-flex justify-center bg-slate-900 text-slate-50 dark:bg-slate-900 dark:text-slate-300 active">Learn more</a> </div>
                    </div>
                </div>
                <div class="card active">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base menu-open">
                        <div class="items-center text-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white">Sales Automation</h3>
                            <p class="card-text my-7">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p> <a href="card.html" class="btn inline-flex justify-center bg-slate-900 text-slate-50 dark:bg-slate-900 dark:text-slate-300 active">Learn more</a> </div>
                    </div>
                </div>
                <div class="card active">
                    <div class="card-body rounded-md bg-white dark:bg-slate-800 shadow-base menu-open">
                        <div class="items-center text-center p-5">
                            <h3 class="card-title text-slate-900 dark:text-white">Sales Automation</h3>
                            <p class="card-text my-7">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p> <a href="card.html" class="btn flex justify-center bg-slate-900 text-slate-50 dark:bg-slate-900 dark:text-slate-300 active">
                                  Learn more</a> </div>
                    </div>
                </div>
            </div>
            <div class="grid gap-4 grid-cols-12">
                <div class="xl:col-span-8 col-span-12">
                    <div class="card rounded-md bg-white dark:bg-slate-800 shadow-base">
                        <div class="card-body flex flex-col p-6 active">
                            <div class="image-box mb-6"> <img src="/images/all-img/post-1.png" alt="" class="block w-full h-full object-cover"> </div>
                            <div class="card-text h-full menu-open active">
                                <div class="flex justify-between mb-4 menu-open">
                                    <a href="card.html" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal active">
                                        <iconify-icon class="text-secondary-500 ltr:mr-2 rtl:ml-2 text-lg" icon="heroicons-outline:calendar"></iconify-icon> 10/02/2021 </a>
                                    <div class="flex space-x-4 rtl:space-x-reverse">
                                        <a href="card.html" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal active">
                                            <iconify-icon class="text-secondary-500 ltr:mr-2 rtl:ml-2 text-lg" icon="heroicons-outline:chat"></iconify-icon> 3 </a>
                                        <a href="card.html" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal active">
                                            <iconify-icon class="text-secondary-500 ltr:mr-2 rtl:ml-2 text-lg" icon="heroicons-outline:share"></iconify-icon> 4 </a>
                                    </div>
                                </div>
                                <h5 class="card-title text-slate-900 dark:text-white">
                                    At Healthcare you will be treated by caring
                                  </h5>
                                <div class="card-text mt-4">
                                    <p> Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip.Lorem ipsum dolor sit amet, consectetur adipiscing eli. </p>
                                    <button class="btn inline-flex justify-center btn-outline-dark mt-8"> Read more </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="xl:col-span-4 col-span-12 space-y-4">
                    <div class="card rounded-md bg-white dark:bg-slate-800  shadow-base">
                        <div class="card-body flex flex-col p-6 active">
                            <div class="image-box order-0 -mx-6 -mt-6 mb-6"> <img src="/images/all-img/post-1.png" alt="" class="block w-full h-full object-cover"> </div>
                            <div class="order-2 card-text h-full menu-open active">
                                <div class="flex justify-between mb-4">
                                    <div>
                                        <div class="text-xl text-slate-900 dark:text-white"> Lorem ipsum </div>
                                    </div>
                                    <a href="card.html" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal active">
                                        <iconify-icon class="text-secondary-500 ltr:mr-2 rtl:ml-2 text-lg" icon="heroicons-outline:calendar"></iconify-icon> 10/02/2021 </a>
                                </div>
                                <div class="card-text mt-4 menu-open">
                                    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
                                    <div class="mt-4 space-x-4 rtl:space-x-reverse"> <a href="card.html" class="btn-link active">Learn more</a> </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="card rounded-md bg-white dark:bg-slate-800 shadow-base">
                        <div class="card-body flex flex-col p-6 active">
                            <div class="card-text h-full menu-open active">
                                <div class="flex justify-between mb-4">
                                    <div>
                                        <div class="text-xl text-slate-900 dark:text-white"> Lorem ipsum </div>
                                    </div>
                                    <a href="card.html" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal active">
                                        <iconify-icon class="text-secondary-500 ltr:mr-2 rtl:ml-2 text-lg" icon="heroicons-outline:calendar"></iconify-icon> 10/02/2021 </a>
                                </div>
                                <div class="card-text mt-4 menu-open active">
                                    <p> Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip.Lorem ipsum dolor sit amet, consectetur adipiscing eli. </p>
                                    <div class="mt-6 flex justify-between menu-open"> <a href="card.html" class="btn-link active">Learn more</a>
                                        <div class="flex space-x-4 rtl:space-x-reverse">
                                            <a href="card.html" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal active">
                                                <iconify-icon class="text-secondary-500 ltr:mr-2 rtl:ml-2 text-lg" icon="heroicons-outline:chat"></iconify-icon> 3 </a>
                                            <a href="card.html" class="inline-flex leading-5 text-slate-500 dark:text-slate-400 text-sm font-normal active">
                                                <iconify-icon class="text-secondary-500 ltr:mr-2 rtl:ml-2 text-lg" icon="heroicons-outline:share"></iconify-icon> 4 </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="grid lg:grid-cols-2 grid-cols-1 gap-4">
                <div class="card">
                    <div class="card-body p-6">
                        <div class="card-text h-full">
                            <div class="flex">
                                <div class="flex-0 mr-6">
                                    <div class="author-img w-[65px] h-[88px] rounded-[40px]"> <img src="/images/all-img/t1.png" alt="image" class="w-full h-full object-cover"> </div>
                                </div>
                                <div class="flex-1">
                                    <p class="mb-4 text-base"> “Amet minim mollit non deserunt ullamco est sit aliqua dolor do amet sintsin. Velit officia consequat duis enim of velit mollit.” </p>
                                    <div class="space-x-5"> <span class="inline-block font-medium text-base">Marvin McKinney</span> <span class="inline-block">CEO at Bitspin</span> </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card rounded-md bg-white dark:bg-slate-800 flex items-center  shadow-base text-center h-auto">
                    <div class="card-text p-6">
                        <p class="text-2xl text-slate-600 dark:text-slate-300"> “Amet minim mollit non deserunt ullamco est sit aliqua dolor do amet sintsin. Velit officia consequat duis enim of velit mollit.” </p>
                    </div>
                </div>
            </div>
            <!-- BEGIN: Colored Background Card -->
            <div class="grid xl:grid-cols-3 md:grid-cols-2 grid-cols-1 gap-5">
                <div class="card rounded-md shadow-base !bg-primary-500 dark:!bg-primary-500">
                    <div class="card-body p-6">
                        <div class="flex-1 mb-5 items-center">
                            <h3 class="card-title !text-white">primary
                                  Card</h3> </div>
                        <div class="card-text">
                            <p class="text-white">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card rounded-md shadow-base !bg-secondary-500 dark:!bg-secondary-500">
                    <div class="card-body p-6">
                        <div class="flex-1 mb-5 items-center">
                            <h3 class="card-title !text-white">secondary
                                  Card</h3> </div>
                        <div class="card-text">
                            <p class="text-white">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card rounded-md shadow-base !bg-info-500 dark:!bg-info-500">
                    <div class="card-body p-6">
                        <div class="flex-1 mb-5 items-center">
                            <h3 class="card-title !text-white">info
                                  Card</h3> </div>
                        <div class="card-text">
                            <p class="text-white">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card rounded-md shadow-base !bg-success-500 dark:!bg-success-500">
                    <div class="card-body p-6">
                        <div class="flex-1 mb-5 items-center">
                            <h3 class="card-title !text-white">success
                                  Card</h3> </div>
                        <div class="card-text">
                            <p class="text-white">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card rounded-md shadow-base !bg-warning-500 dark:!bg-warning-500">
                    <div class="card-body p-6">
                        <div class="flex-1 mb-5 items-center">
                            <h3 class="card-title !text-white">warning
                                  Card</h3> </div>
                        <div class="card-text">
                            <p class="text-white">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card rounded-md shadow-base !bg-danger-500 dark:!bg-danger-500">
                    <div class="card-body p-6">
                        <div class="flex-1 mb-5 items-center">
                            <h3 class="card-title !text-white">danger
                                  Card</h3> </div>
                        <div class="card-text">
                            <p class="text-white">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Colored Background Card -->
            <!-- BEGIN: Borderd Card -->
            <div class="grid xl:grid-cols-3 md:grid-cols-2 grid-cols-1 gap-5">
                <div class="card ring-1 ring-primary-500">
                    <div class="card-body p-6">
                        <div class="flex-1 items-center">
                            <div class="card-title mb-5">primary Card</div>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card ring-1 ring-secondary-500">
                    <div class="card-body p-6">
                        <div class="flex-1 items-center">
                            <div class="card-title mb-5">secondary Card</div>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card ring-1 ring-info-500">
                    <div class="card-body p-6">
                        <div class="flex-1 items-center">
                            <div class="card-title mb-5">info Card</div>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card ring-1 ring-success-500">
                    <div class="card-body p-6">
                        <div class="flex-1 items-center">
                            <div class="card-title mb-5">success Card</div>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card ring-1 ring-warning-500">
                    <div class="card-body p-6">
                        <div class="flex-1 items-center">
                            <div class="card-title mb-5">warning Card</div>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
                <div class="card ring-1 ring-danger-500">
                    <div class="card-body p-6">
                        <div class="flex-1 items-center">
                            <div class="card-title mb-5">danger Card</div>
                            <p class="card-text">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Bordered Card -->
            <!-- BEGIN: Icon Title Card -->
            <div class="grid xl:grid-cols-3 md:grid-cols-2 grid-cols-1 gap-5">
                <div class="card">
                    <div class="card-body">
                        <div class="card-text h-full">
                            <header class="border-b px-4 pt-4 pb-3 flex items-center border-primary-500">
                                <iconify-icon class="text-3xl inline-block ltr:mr-2 rtl:ml-2 text-primary-500" icon="fluent:settings-28-regular"></iconify-icon>
                                <h3 class="card-title mb-0 text-primary-500">primary
                                    Card</h3> </header>
                            <div class="py-3 px-5">
                                <h5 class="card-subtitle">Card Subtitle</h5>
                                <p class="card-text mt-3">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="card-text h-full">
                            <header class="border-b px-4 pt-4 pb-3 flex items-center border-secondary-500">
                                <iconify-icon class="text-3xl inline-block ltr:mr-2 rtl:ml-2 text-secondary-500" icon="material-symbols:stop-circle-outline-rounded"></iconify-icon>
                                <h3 class="card-title mb-0 text-secondary-500">secondary
                                    Card</h3> </header>
                            <div class="py-3 px-5">
                                <h5 class="card-subtitle">Card Subtitle</h5>
                                <p class="card-text mt-3">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="card-text h-full">
                            <header class="border-b px-4 pt-4 pb-3 flex items-center border-info-500">
                                <iconify-icon class="text-3xl inline-block ltr:mr-2 rtl:ml-2 text-info-500" icon="ph:info"></iconify-icon>
                                <h3 class="card-title mb-0 text-info-500">info
                                    Card</h3> </header>
                            <div class="py-3 px-5">
                                <h5 class="card-subtitle">Card Subtitle</h5>
                                <p class="card-text mt-3">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="card-text h-full">
                            <header class="border-b px-4 pt-4 pb-3 flex items-center border-success-500">
                                <iconify-icon class="text-3xl inline-block ltr:mr-2 rtl:ml-2 text-success-500" icon="ph:circle-wavy-check"></iconify-icon>
                                <h3 class="card-title mb-0 text-success-500">success
                                    Card</h3> </header>
                            <div class="py-3 px-5">
                                <h5 class="card-subtitle">Card Subtitle</h5>
                                <p class="card-text mt-3">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="card-text h-full">
                            <header class="border-b px-4 pt-4 pb-3 flex items-center border-warning-500">
                                <iconify-icon class="text-3xl inline-block ltr:mr-2 rtl:ml-2 text-warning-500" icon="ic:round-warning-amber"></iconify-icon>
                                <h3 class="card-title mb-0 text-warning-500">warning
                                    Card</h3> </header>
                            <div class="py-3 px-5">
                                <h5 class="card-subtitle">Card Subtitle</h5>
                                <p class="card-text mt-3">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="card-text h-full">
                            <header class="border-b px-4 pt-4 pb-3 flex items-center border-danger-500">
                                <iconify-icon class="text-3xl inline-block ltr:mr-2 rtl:ml-2 text-danger-500" icon="material-symbols:dangerous-outline-rounded"></iconify-icon>
                                <h3 class="card-title mb-0 text-danger-500">danger
                                    Card</h3> </header>
                            <div class="py-3 px-5">
                                <h5 class="card-subtitle">Card Subtitle</h5>
                                <p class="card-text mt-3">Lorem ipsum dolor sit amet, consec tetur adipiscing elit, sed do eiusmod tempor incididun ut labore et dolor magna aliqua.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- BEGIN: Icon Title Card -->
        </div>
    </div>
</x-app-layout>
