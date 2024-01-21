<x-app-layout>
    <div class="space-y-8">
        {{-- <div>--}}
        {{-- <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />--}}
        {{-- </div>--}}

        <div class="space-y-5">
            <div class="grid grid-cols-12 gap-5">
              <div class="xl:col-span-3 col-span-12 lg:col-span-5 ">
                <div class="card p-6 h-full">
                  <div class="space-y-5">
                    <div class="xl:col-span-8 col-span-12">
                      <div class="grid sm:grid-cols-2 grid-cols-1 gap-3">

                        <div class="bg-info-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-50 text-center">
                            <div class="text-info-500 mx-auto h-10 w-10 flex flex-col items-center justify-center rounded-full bg-white text-2xl mb-4">
                                <iconify-icon icon="heroicons-outline:menu-alt-1"></iconify-icon>
                            </div>
                            <span class="block text-sm text-slate-600 font-medium dark:text-white mb-1">
                                Total Task
                            </span>
                            <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium">
                                64
                            </span>
                        </div>
                        <div class="bg-warning-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-50 text-center">
                            <div class="text-warning-500 mx-auto h-10 w-10 flex flex-col items-center justify-center rounded-full bg-white text-2xl mb-4">
                                <iconify-icon icon="heroicons-outline:chart-pie"></iconify-icon>
                            </div>
                            <span class="block text-sm text-slate-600 font-medium dark:text-white mb-1">
                                Completed
                            </span>
                            <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium">
                                45
                            </span>
                        </div>
                        <div class="bg-primary-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-50 text-center">
                            <div class="text-primary-500 mx-auto h-10 w-10 flex flex-col items-center justify-center rounded-full bg-white text-2xl mb-4">
                                <iconify-icon icon="heroicons-outline:clock"></iconify-icon>
                            </div>
                            <span class="block text-sm text-slate-600 font-medium dark:text-white mb-1">
                                Hours
                            </span>
                            <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium">
                                190
                            </span>
                        </div>
                        <div class="bg-success-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-50 text-center">
                            <div class="text-success-500 mx-auto h-10 w-10 flex flex-col items-center justify-center rounded-full bg-white text-2xl mb-4">
                                <iconify-icon icon="heroicons-outline:calculator"></iconify-icon>
                            </div>
                            <span class="block text-sm text-slate-600 font-medium dark:text-white mb-1">
                                Spendings
                            </span>
                            <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium">
                                $3,564
                            </span>
                        </div>

                      </div>
                    </div>
                    <div class="bg-slate-50 dark:bg-slate-900 rounded-md p-4">
                      <span class="block dark:text-slate-400 text-sm text-slate-600">
                        Progress
                      </span>
                      <div class="donut-chart" height="110" colors="#0CE7FA,#E2F6FD"></div>
                    </div>
                  </div>
                </div>
              </div>
              <div class="xl:col-span-5 col-span-12 lg:col-span-7">
                <div class="card h-full">
                  <div class="card-header">
                    <h4 class="card-title">About Project</h4>
                  </div>
                  <div class="card-body p-6">
                    <div>
                      <div class="text-base font-medium text-slate-800 dark:text-slate-100 mb-3">
                        Background information
                      </div>
                      <p class="text-sm text-slate-600 dark:text-slate-300">
                        The Optimistic Website Company - Amet minim mollit non deserunt ullamco est sit aliqua dolor do amet sint.
                      </p>
                      <br/>
                      <p class="text-sm text-slate-600 dark:text-slate-300">
                        Amet minim mollit non deserunt ullamco est sit aliqua dolor do amet sint.The Optimistic Website Company - Amet minim
                        Amet minim mollit non deserunt ullamco est sit aliqua dolor do amet sint.The Optimistic Website Company - Amet minim
                        mollit non deserunt ullamco est sit aliqua dolor do amet sint. Velit officia consequat duis enim velit mollit. Exercita
                        -tion veniam consequat sunt nostrud amet.
                      </p>
                      <div class="flex flex-wrap mt-8">
                        <div class="xl:mr-8 mr-4 mb-3 space-y-1">
                          <div class="font-semibold text-slate-500 dark:text-slate-400">
                            Existing website
                          </div>
                          <div class="flex items-center space-x-2 text-xs font-normal text-primary-600 dark:text-slate-300 rtl:space-x-reverse">
                            <iconify-icon icon="heroicons:link"></iconify-icon>
                            <a href="#">www.example.com</a>
                          </div>
                        </div>
                        <div class="xl:mr-8 mr-4 mb-3 space-y-1">
                          <div class="font-semibold text-slate-500 dark:text-slate-400">
                            Project brief
                          </div>
                          <div class="flex items-center space-x-2 text-xs font-normal text-primary-600 dark:text-slate-300 rtl:space-x-reverse">
                            <iconify-icon icon="heroicons:link"></iconify-icon>
                            <a href="#">www.example.com</a>
                          </div>
                        </div>
                      </div>
                      <div class="bg-slate-100 dark:bg-slate-700 rounded px-4 pt-4 pb-1 flex flex-wrap justify-between mt-6">
                        <div class="mr-3 mb-3 space-y-2">
                          <div class="text-xs font-medium text-slate-600 dark:text-slate-300">
                            Project owner
                          </div>
                          <div class="text-xs text-slate-600 dark:text-slate-300">
                            John Doe
                          </div>
                        </div>
                        <div class="mr-3 mb-3 space-y-2">
                          <div class="text-xs font-medium text-slate-600 dark:text-slate-300">
                            Budget
                          </div>
                          <div class="text-xs text-slate-600 dark:text-slate-300">
                            $75,800
                          </div>
                        </div>
                        <div class="mr-3 mb-3 space-y-2">
                          <div class="text-xs font-medium text-slate-600 dark:text-slate-300">
                            Start date
                          </div>
                          <div class="text-xs text-slate-600 dark:text-slate-300">
                            01/11/2021
                          </div>
                        </div>
                        <div class="mr-3 mb-3 space-y-2">
                          <div class="text-xs font-medium text-slate-600 dark:text-slate-300">
                            Deadline
                          </div>
                          <div class="text-xs text-warning-500">01/11/2021</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div class="lg:col-span-4 col-span-12 space-y-5">
                <div class="card">
                  <div class="card-header">
                    <h4 class="card-title">Notes</h4>
                  </div>
                  <div class="card-body p-6">
                    <x-calender-note />
                  </div>
                </div>
              </div>
            </div>
            <div class="grid xl:grid-cols-3 grid-cols-1 gap-5">
              <div class="card">
                <div class="card-header">
                  <h4 class="card-title">Task list</h4>
                  <div>...</div>
                </div>
                <div class="card-body p-6">
                    <!-- BEGIN: Task List -->
                    <div>
                        <ul class="divide-y divide-slate-100 dark:divide-slate-700 -mx-6 -mb-6">
                            <li class="flex items-center px-6 space-x-4 py-4 rtl:space-x-reverse completed">
                                <div class="flex-none flex space-x-2 items-center rtl:space-x-reverse ">
                                    <div class="checkbox-area">
                                        <label class="inline-flex items-center cursor-pointer">
                                            <input type="checkbox" class="hidden" name="tasklist" value="true" checked>
                                            <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                            <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                        </label>
                                    </div>
                                    <div class="img-active
                                        h-8 w-8 rounded-full text-white">
                                        <img src="images/users/user-1.jpg" alt="" class="block w-full h-full object-cover rounded-full">
                                    </div>
                                </div>
                                <div class="flex-1 flex bar-active">
                                    <span class="flex-1 text-sm text-slate-600 dark:text-slate-300">
                                    Amet minim mollit no...
                                    </span>
                                    <span class="flex-none space-x-2 text-base text-secondary-500 rtl:space-x-reverse">
                                        <button type="button" class="transition duration-150 hover:text-danger-500">
                                            <iconify-icon icon="heroicons-outline:trash"></iconify-icon>
                                        </button>
                                    </span>
                                </div>
                            </li>
                            <li class="flex items-center px-6 space-x-4 py-4 rtl:space-x-reverse">
                                <div class="flex-none flex space-x-2 items-center rtl:space-x-reverse">
                                    <div class="checkbox-area">
                                        <label class="inline-flex items-center cursor-pointer">
                                        <input type="checkbox" class="hidden" name="tasklist">
                                        <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                        </label>
                                    </div>
                                    <div class="img-active
                                        h-8 w-8 rounded-full text-white">
                                        <img src="images/users/user-2.jpg" alt="" class="block w-full h-full object-cover rounded-full">
                                    </div>
                                </div>
                                <div class="flex-1 flex bar-active">
                                    <span class="flex-1 text-sm text-slate-600 dark:text-slate-300">
                                    Amet minim mollit no...
                                    </span>
                                    <span class="flex-none space-x-2 text-base text-secondary-500 rtl:space-x-reverse">
                                        <button type="button" class="transition duration-150 hover:text-danger-500">
                                            <iconify-icon icon="heroicons-outline:trash"></iconify-icon>
                                        </button>
                                    </span>
                                </div>
                            </li>
                            <li class="flex items-center px-6 space-x-4 py-4 rtl:space-x-reverse">
                                <div class="flex-none flex space-x-2 items-center rtl:space-x-reverse">
                                    <div class="checkbox-area">
                                        <label class="inline-flex items-center cursor-pointer">
                                        <input type="checkbox" class="hidden" name="tasklist">
                                        <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                        </label>
                                    </div>
                                    <div class="img-active
                                        h-8 w-8 rounded-full text-white">
                                        <img src="images/users/user-3.jpg" alt="" class="block w-full h-full object-cover rounded-full">
                                    </div>
                                </div>
                                <div class="flex-1 flex bar-active">
                                    <span class="flex-1 text-sm text-slate-600 dark:text-slate-300">
                                    Amet minim mollit no...
                                    </span>
                                    <span class="flex-none space-x-2 text-base text-secondary-500 rtl:space-x-reverse">
                                        <button type="button" class="transition duration-150 hover:text-danger-500">
                                            <iconify-icon icon="heroicons-outline:trash"></iconify-icon>
                                        </button>
                                    </span>
                                </div>
                            </li>
                            <li class="flex items-center px-6 space-x-4 py-4 rtl:space-x-reverse">
                                <div class="flex-none flex space-x-2 items-center rtl:space-x-reverse">
                                    <div class="checkbox-area">
                                        <label class="inline-flex items-center cursor-pointer">
                                        <input type="checkbox" class="hidden" name="tasklist">
                                        <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                        </label>
                                    </div>
                                    <div class="img-active
                                        h-8 w-8 rounded-full text-white">
                                        <img src="images/users/user-4.jpg" alt="" class="block w-full h-full object-cover rounded-full">
                                    </div>
                                </div>
                                <div class="flex-1 flex bar-active">
                                    <span class="flex-1 text-sm text-slate-600 dark:text-slate-300">
                                    Amet minim mollit no...
                                    </span>
                                    <span class="flex-none space-x-2 text-base text-secondary-500 rtl:space-x-reverse">
                                        <button type="button" class="transition duration-150 hover:text-danger-500">
                                            <iconify-icon icon="heroicons-outline:trash"></iconify-icon>
                                        </button>
                                    </span>
                                </div>
                            </li>
                            <li class="flex items-center px-6 space-x-4 py-4 rtl:space-x-reverse">
                                <div class="flex-none flex space-x-2 items-center rtl:space-x-reverse">
                                    <div class="checkbox-area">
                                        <label class="inline-flex items-center cursor-pointer">
                                        <input type="checkbox" class="hidden" name="tasklist">
                                        <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                        </label>
                                    </div>
                                    <div class="img-active
                                        h-8 w-8 rounded-full text-white">
                                        <img src="images/users/user-5.jpg" alt="" class="block w-full h-full object-cover rounded-full">
                                    </div>
                                </div>
                                <div class="flex-1 flex bar-active">
                                    <span class="flex-1 text-sm text-slate-600 dark:text-slate-300">
                                    Amet minim mollit no...
                                    </span>
                                    <span class="flex-none space-x-2 text-base text-secondary-500 rtl:space-x-reverse">
                                        <button type="button" class="transition duration-150 hover:text-danger-500">
                                            <iconify-icon icon="heroicons-outline:trash"></iconify-icon>
                                        </button>
                                    </span>
                                </div>
                            </li>
                            <li class="flex items-center px-6 space-x-4 py-4 rtl:space-x-reverse">
                                <div class="flex-none flex space-x-2 items-center rtl:space-x-reverse">
                                    <div class="checkbox-area">
                                        <label class="inline-flex items-center cursor-pointer">
                                        <input type="checkbox" class="hidden" name="tasklist">
                                        <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                        </label>
                                    </div>
                                    <div class="img-active
                                        h-8 w-8 rounded-full text-white">
                                        <img src="images/users/user-6.jpg" alt="" class="block w-full h-full object-cover rounded-full">
                                    </div>
                                </div>
                                <div class="flex-1 flex bar-active">
                                    <span class="flex-1 text-sm text-slate-600 dark:text-slate-300">
                                    Amet minim mollit no...
                                    </span>
                                    <span class="flex-none space-x-2 text-base text-secondary-500 rtl:space-x-reverse">
                                        <button type="button" class="transition duration-150 hover:text-danger-500">
                                            <iconify-icon icon="heroicons-outline:trash"></iconify-icon>
                                        </button>
                                    </span>
                                </div>
                            </li>
                        </ul>
                    </div>
                    <!-- END: Task List -->
                </div>
              </div>
              <!-- end task -->
              <div class="card">
                <div class="card-header">
                  <h4 class="card-title">Messages</h4>
                  <div>...</div>
                </div>
                <div class="card-body p-6">
                    <!-- BEGIN: Message -->
                    <div>
                        <ul class="divide-y divide-slate-100 dark:divide-slate-700 -mx-6 -mb-6">
                            <li>
                                <a href="{{ route('chat') }}" class="hover:bg-slate-100 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-slate-800 text-slate-600 dark:text-slate-300 block w-full px-4 py-3 text-sm mb-2 last:mb-0 cursor-pointer">
                                    <div class="flex ltr:text-left rtl:text-right">
                                        <div class="flex-none ltr:mr-3 rtl:ml-3">
                                            <div class="h-8 w-8 bg-white dark:bg-slate-700 rounded-full relative">
                                                <span class="
                                                    bg-secondary-500
                                                    w-[10px] h-[10px] rounded-full border border-white dark:border-slate-700  inline-block absolute right-0 top-0"></span>
                                                <img src="images/all-img/user.png" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <div class="text-slate-800 dark:text-slate-300 text-sm font-medium mb-1`">
                                                Wade Warren
                                            </div>
                                            <div class="text-xs hover:text-[#68768A] font-normal text-slate-600 dark:text-slate-300">
                                                Hi! How are you doing?.....
                                            </div>
                                            <div class="text-slate-400 dark:text-slate-400 text-xs mt-1">
                                                3 min ago
                                            </div>
                                        </div>
                                        <div class="flex-0">
                                            <span class="h-4 w-4 bg-danger-500 border border-none rounded-full text-[10px] flex items-center justify-center text-white">
                                            1
                                            </span>
                                        </div>
                                    </div>
                                </a>
                            </li>
                            <li>
                                <a href="{{ route('chat') }}" class="hover:bg-slate-100 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-slate-800 text-slate-600 dark:text-slate-300 block w-full px-4 py-3 text-sm mb-2 last:mb-0 cursor-pointer">
                                    <div class="flex ltr:text-left rtl:text-right">
                                        <div class="flex-none ltr:mr-3 rtl:ml-3">
                                            <div class="h-8 w-8 bg-white dark:bg-slate-700 rounded-full relative">
                                                <span class="
                                                    bg-success-500
                                                    w-[10px] h-[10px] rounded-full border border-white dark:border-slate-700  inline-block absolute right-0 top-0"></span>
                                                <img src="images/all-img/user3.png" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <div class="text-slate-800 dark:text-slate-300 text-sm font-medium mb-1`">
                                                Savannah Nguyen
                                            </div>
                                            <div class="text-xs hover:text-[#68768A] font-normal text-slate-600 dark:text-slate-300">
                                                Hi! How are you doing?.....
                                            </div>
                                            <div class="text-slate-400 dark:text-slate-400 text-xs mt-1">
                                                3 min ago
                                            </div>
                                        </div>
                                    </div>
                                </a>
                            </li>
                            <li>
                                <a href="{{ route('chat') }}" class="hover:bg-slate-100 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-slate-800 text-slate-600 dark:text-slate-300 block w-full px-4 py-3 text-sm mb-2 last:mb-0 cursor-pointer">
                                    <div class="flex ltr:text-left rtl:text-right">
                                        <div class="flex-none ltr:mr-3 rtl:ml-3">
                                            <div class="h-8 w-8 bg-white dark:bg-slate-700 rounded-full relative">
                                                <span class="
                                                    bg-success-500
                                                    w-[10px] h-[10px] rounded-full border border-white dark:border-slate-700  inline-block absolute right-0 top-0"></span>
                                                <img src="images/all-img/user3.png" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <div class="text-slate-800 dark:text-slate-300 text-sm font-medium mb-1`">
                                                Ralph Edwards
                                            </div>
                                            <div class="text-xs hover:text-[#68768A] font-normal text-slate-600 dark:text-slate-300">
                                                Hi! How are you doing?.....
                                            </div>
                                            <div class="text-slate-400 dark:text-slate-400 text-xs mt-1">
                                                3 min ago
                                            </div>
                                        </div>
                                        <div class="flex-0">
                                            <span class="h-4 w-4 bg-danger-500 border border-none rounded-full text-[10px] flex items-center justify-center text-white">
                                            8
                                            </span>
                                        </div>
                                    </div>
                                </a>
                            </li>
                            <li>
                                <a href="{{ route('chat') }}" class="hover:bg-slate-100 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-slate-800 text-slate-600 dark:text-slate-300 block w-full px-4 py-3 text-sm mb-2 last:mb-0 cursor-pointer">
                                    <div class="flex ltr:text-left rtl:text-right">
                                        <div class="flex-none ltr:mr-3 rtl:ml-3">
                                            <div class="h-8 w-8 bg-white dark:bg-slate-700 rounded-full relative">
                                                <span class="
                                                    bg-secondary-500
                                                    w-[10px] h-[10px] rounded-full border border-white dark:border-slate-700  inline-block absolute right-0 top-0"></span>
                                                <img src="images/all-img/user4.png" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <div class="text-slate-800 dark:text-slate-300 text-sm font-medium mb-1`">
                                                Cody Fisher
                                            </div>
                                            <div class="text-xs hover:text-[#68768A] font-normal text-slate-600 dark:text-slate-300">
                                                Hi! How are you doing?.....
                                            </div>
                                            <div class="text-slate-400 dark:text-slate-400 text-xs mt-1">
                                                3 min ago
                                            </div>
                                        </div>
                                    </div>
                                </a>
                            </li>
                            <li>
                                <a href="{{ route('chat') }}" class="hover:bg-slate-100 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-slate-800 text-slate-600 dark:text-slate-300 block w-full px-4 py-3 text-sm mb-2 last:mb-0 cursor-pointer">
                                    <div class="flex ltr:text-left rtl:text-right">
                                        <div class="flex-none ltr:mr-3 rtl:ml-3">
                                            <div class="h-8 w-8 bg-white dark:bg-slate-700 rounded-full relative">
                                                <span class="
                                                    bg-success-500
                                                    w-[10px] h-[10px] rounded-full border border-white dark:border-slate-700  inline-block absolute right-0 top-0"></span>
                                                <img src="images/all-img/user3.png" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <div class="text-slate-800 dark:text-slate-300 text-sm font-medium mb-1`">
                                                Savannah Nguyen
                                            </div>
                                            <div class="text-xs hover:text-[#68768A] font-normal text-slate-600 dark:text-slate-300">
                                                Hi! How are you doing?.....
                                            </div>
                                            <div class="text-slate-400 dark:text-slate-400 text-xs mt-1">
                                                3 min ago
                                            </div>
                                        </div>
                                    </div>
                                </a>
                            </li>
                        </ul>
                    </div>
                    <!-- END: Message  -->
                </div>
              </div>
              <!-- end message -->
              <div class="card">
                <div class="card-header">
                  <h4 class="card-title">Activity</h4>
                  <div>...</div>
                </div>
                <div class="card-body p-6">
                    <!-- BEGIN: Activity Card -->
                    <ul class="relative ltr:pl-2 rtl:pr-2">
                        <li class="ltr:border-l-2 rtl:border-r-2 border-slate-100 dark:border-slate-700 pb-4
                            last:border-none ltr:pl-[22px] rtl:pr-[22px] relative before:absolute ltr:before:left-[-8px]
                            rtl:before:-right-2 before:top-[0px] before:rounded-full before:w-4 before:h-4
                            before:bg-slate-900 dark:before:bg-slate-600 before:leading-[2px]
                            before:content-[url('../images/all-img/ck.svg')]">
                            <div class="p-[10px] relative top-[-20px]">
                                <h2 class="text-sm font-medium dark:text-slate-400-900 mb-1 text-slate-600">
                                    Project start date
                                </h2>
                                <p class="text-xs capitalize dark:text-slate-400">
                                    Sep 20, 2021
                                </p>
                            </div>
                        </li>
                        <li class="ltr:border-l-2 rtl:border-r-2 border-slate-100 dark:border-slate-700 pb-4
                            last:border-none ltr:pl-[22px] rtl:pr-[22px] relative before:absolute ltr:before:left-[-8px]
                            rtl:before:-right-2 before:top-[0px] before:rounded-full before:w-4 before:h-4
                            before:bg-slate-900 dark:before:bg-slate-600 before:leading-[2px]
                            before:content-[url('../images/all-img/ck.svg')]">
                            <div class="p-[10px] relative top-[-20px]">
                                <h2 class="text-sm font-medium dark:text-slate-400-900 mb-1 text-slate-600">
                                    Project start date
                                </h2>
                                <p class="text-xs capitalize dark:text-slate-400">
                                    Sep 20, 2021
                                </p>
                            </div>
                        </li>
                        <li class="ltr:border-l-2 rtl:border-r-2 border-slate-100 dark:border-slate-700 pb-4
                            last:border-none ltr:pl-[22px] rtl:pr-[22px] relative before:absolute ltr:before:left-[-8px]
                            rtl:before:-right-2 before:top-[0px] before:rounded-full before:w-4 before:h-4
                            before:bg-slate-900 dark:before:bg-slate-600 before:leading-[2px]
                            before:content-[url('../images/all-img/ck.svg')]">
                            <div class="p-[10px] relative top-[-20px]">
                                <h2 class="text-sm font-medium dark:text-slate-400-900 mb-1 text-slate-600">
                                    Project start date
                                </h2>
                                <p class="text-xs capitalize dark:text-slate-400">
                                    Sep 20, 2021
                                </p>
                            </div>
                        </li>
                        <li class="ltr:border-l-2 rtl:border-r-2 border-slate-100 dark:border-slate-700 pb-4
                            last:border-none ltr:pl-[22px] rtl:pr-[22px] relative before:absolute ltr:before:left-[-8px]
                            rtl:before:-right-2 before:top-[0px] before:rounded-full before:w-4 before:h-4
                            before:bg-slate-900 dark:before:bg-slate-600 before:leading-[2px]
                            before:content-[url('../images/all-img/ck.svg')]">
                            <div class="p-[10px] relative top-[-20px]">
                                <h2 class="text-sm font-medium dark:text-slate-400-900 mb-1 text-slate-600">
                                    Project start date
                                </h2>
                                <p class="text-xs capitalize dark:text-slate-400">
                                    Sep 20, 2021
                                </p>
                            </div>
                        </li>
                        <li class="ltr:border-l-2 rtl:border-r-2 border-slate-100 dark:border-slate-700 pb-4
                            last:border-none ltr:pl-[22px] rtl:pr-[22px] relative before:absolute ltr:before:left-[-8px]
                            rtl:before:-right-2 before:top-[0px] before:rounded-full before:w-4 before:h-4
                            before:bg-slate-900 dark:before:bg-slate-600 before:leading-[2px]
                            before:content-[url('../images/all-img/ck.svg')]">
                            <div class="p-[10px] relative top-[-20px]">
                                <h2 class="text-sm font-medium dark:text-slate-400-900 mb-1 text-slate-600">
                                    Project start date
                                </h2>
                                <p class="text-xs capitalize dark:text-slate-400">
                                    Sep 20, 2021
                                </p>
                            </div>
                        </li>
                    </ul>
                    <!-- END: Activity Card -->
                </div>
              </div>
              <!-- end activity -->
            </div>
            <div class="grid grid-cols-12 gap-5">
              <div class="xl:col-span-8 lg:col-span-7 col-span-12">
                <div class="card">
                  <div class="card-header noborder">
                    <h4 class="card-title ">Team members</h4>
                    <div>...</div>
                  </div>
                  <div class="card-body p-6">
                        <!-- BEGIN: Team Table -->
                        <div class="overflow-x-auto -mx-6">
                            <div class="inline-block min-w-full align-middle">
                                <div class="overflow-hidden ">
                                    <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700">
                                        <thead class=" bg-slate-200 dark:bg-slate-700">
                                            <tr>
                                                <th scope="col" class=" table-th ">
                                                    ASSIGNEE
                                                </th>
                                                <th scope="col" class=" table-th ">
                                                    STATUS
                                                </th>
                                                <th scope="col" class=" table-th ">
                                                    TIME
                                                </th>
                                                <th scope="col" class=" table-th "></th>
                                                <th scope="col" class=" table-th ">
                                                    ACTION
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                                            <tr>
                                                <td class="table-td">
                                                    <div class="flex items-center">
                                                        <div class="flex-none">
                                                            <div class="w-8 h-8 rounded-[100%] ltr:mr-3 rtl:ml-3">
                                                                <img src="images/users/user-1.jpg" alt="" class="w-full h-full rounded-[100%] object-cover">
                                                            </div>
                                                        </div>
                                                        <div class="flex-1 text-start">
                                                            <h4 class="text-sm font-medium text-slate-600 whitespace-nowrap">
                                                                Arlene McCoy
                                                            </h4>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td class="table-td">
                                                    <span class="block text-left">
                                                        <span class="inline-block text-center mx-auto py-1">
                                                            <span class="flex items-center space-x-3 rtl:space-x-reverse">
                                                                <span class="h-[6px] w-[6px] bg-danger-500 rounded-full inline-block ring-4 ring-opacity-30 ring-danger-500"></span>
                                                                <span>In progress</span>
                                                            </span>
                                                        </span>
                                                    </span>
                                                </td>
                                                <td class="table-td">42.5 hours</td>
                                                <td class="table-td"></td>
                                                <td class="table-td">
                                                    <div class="relative">
                                                        <div class="dropdown relative">
                                                            <button class="text-xl text-center block w-full " type="button" id="teamDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                                                                <iconify-icon icon="heroicons-outline:dots-vertical"></iconify-icon>
                                                            </button>
                                                            <ul class=" dropdown-menu min-w-[120px] absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700
                                                                shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    View</a>
                                                                </li>
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    Edit</a>
                                                                </li>
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    Delete</a>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td class="table-td">
                                                    <div class="flex items-center">
                                                        <div class="flex-none">
                                                            <div class="w-8 h-8 rounded-[100%] ltr:mr-3 rtl:ml-3">
                                                                <img src="images/users/user-2.jpg" alt="" class="w-full h-full rounded-[100%] object-cover">
                                                            </div>
                                                        </div>
                                                        <div class="flex-1 text-start">
                                                            <h4 class="text-sm font-medium text-slate-600 whitespace-nowrap">
                                                                Arlene McCoy
                                                            </h4>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td class="table-td ">
                                                    <span class="block min-w-[140px] text-left">
                                                    <span class="inline-block text-center mx-auto py-1">
                                                    <span class="flex items-center space-x-3 rtl:space-x-reverse">
                                                    <span class="h-[6px] w-[6px] bg-success-500 rounded-full inline-block ring-4 ring-opacity-30 ring-success-500"></span>
                                                    <span>Complete</span>
                                                    </span>
                                                    </span>
                                                    </span>
                                                </td>
                                                <td class="table-td">42.5 hours</td>
                                                <td class="table-td"></td>
                                                <td class="table-td">
                                                    <div class="relative">
                                                        <div class="dropdown relative">
                                                            <button class="text-xl text-center block w-full " type="button" id="teamDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                                                                <iconify-icon icon="heroicons-outline:dots-vertical"></iconify-icon>
                                                            </button>
                                                            <ul class=" dropdown-menu min-w-[120px] absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700
                                                                shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    View</a>
                                                                </li>
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    Edit</a>
                                                                </li>
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    Delete</a>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td class="table-td">
                                                    <div class="flex items-center">
                                                        <div class="flex-none">
                                                            <div class="w-8 h-8 rounded-[100%] ltr:mr-3 rtl:ml-3">
                                                                <img src="images/users/user-3.jpg" alt="" class="w-full h-full rounded-[100%] object-cover">
                                                            </div>
                                                        </div>
                                                        <div class="flex-1 text-start">
                                                            <h4 class="text-sm font-medium text-slate-600 whitespace-nowrap">
                                                                Arlene McCoy
                                                            </h4>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td class="table-td ">
                                                    <span class="block min-w-[140px] text-left">
                                                    <span class="inline-block text-center mx-auto py-1">
                                                    <span class="flex items-center space-x-3 rtl:space-x-reverse">
                                                    <span class="h-[6px] w-[6px] bg-danger-500 rounded-full inline-block ring-4 ring-opacity-30 ring-danger-500"></span>
                                                    <span>In progress</span>
                                                    </span>
                                                    </span></span>
                                                </td>
                                                <td class="table-td">42.5 hours</td>
                                                <td class="table-td"></td>
                                                <td class="table-td">
                                                    <div class="relative">
                                                        <div class="dropdown relative">
                                                            <button class="text-xl text-center block w-full " type="button" id="teamDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                                                                <iconify-icon icon="heroicons-outline:dots-vertical"></iconify-icon>
                                                            </button>
                                                            <ul class=" dropdown-menu min-w-[120px] absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700
                                                                shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    View</a>
                                                                </li>
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    Edit</a>
                                                                </li>
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    Delete</a>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td class="table-td">
                                                    <div class="flex items-center">
                                                        <div class="flex-none">
                                                            <div class="w-8 h-8 rounded-[100%] ltr:mr-3 rtl:ml-3">
                                                                <img src="images/users/user-4.jpg" alt="" class="w-full h-full rounded-[100%] object-cover">
                                                            </div>
                                                        </div>
                                                        <div class="flex-1 text-start">
                                                            <h4 class="text-sm font-medium text-slate-600 whitespace-nowrap">
                                                                Arlene McCoy
                                                            </h4>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td class="table-td ">
                                                    <span class="block min-w-[140px] text-left">
                                                    <span class="inline-block text-center mx-auto py-1">
                                                    <span class="flex items-center space-x-3 rtl:space-x-reverse">
                                                    <span class="h-[6px] w-[6px] bg-success-500 rounded-full inline-block ring-4 ring-opacity-30 ring-success-500"></span>
                                                    <span>Complete</span>
                                                    </span>
                                                    </span>
                                                    </span>
                                                </td>
                                                <td class="table-td">42.5 hours</td>
                                                <td class="table-td"></td>
                                                <td class="table-td">
                                                    <div class="relative">
                                                        <div class="dropdown relative">
                                                            <button class="text-xl text-center block w-full " type="button" id="teamDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                                                                <iconify-icon icon="heroicons-outline:dots-vertical"></iconify-icon>
                                                            </button>
                                                            <ul class=" dropdown-menu min-w-[120px] absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700
                                                                shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    View</a>
                                                                </li>
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    Edit</a>
                                                                </li>
                                                                <li>
                                                                    <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                                        dark:hover:text-white">
                                                                    Delete</a>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                        <!-- END: Team table -->
                  </div>
                </div>
              </div>
              <div class="xl:col-span-4 lg:col-span-5 col-span-12">
                <div class="card h-full">
                  <div class="card-header">
                    <h4 class="card-title">Files</h4>
                    <div>...</div>
                  </div>
                  <div class="card-body p-6">
                        <!-- BEGIN: Files Card -->
                        <ul class="divide-y divide-slate-100 dark:divide-slate-700">
                            <li class="block py-[8px]">
                                <div class="flex space-x-2 rtl:space-x-reverse">
                                    <div class="flex-1 flex space-x-2 rtl:space-x-reverse">
                                        <div class="flex-none">
                                            <div class="h-8 w-8">
                                                <img src="images/icon/file-1.svg" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <span class="block text-slate-600 text-sm dark:text-slate-300">
                                            Dashboard.fig
                                            </span>
                                            <span class="block font-normal text-xs text-slate-500 mt-1">
                                            06 June 2021 / 155MB
                                            </span>
                                        </div>
                                    </div>
                                    <div class="flex-none">
                                        <button type="button" class="text-xs text-slate-900 dark:text-white">
                                        Download
                                        </button>
                                    </div>
                                </div>
                            </li>
                            <li class="block py-[8px]">
                                <div class="flex space-x-2 rtl:space-x-reverse">
                                    <div class="flex-1 flex space-x-2 rtl:space-x-reverse">
                                        <div class="flex-none">
                                            <div class="h-8 w-8">
                                                <img src="images/icon/pdf-1.svg" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <span class="block text-slate-600 text-sm dark:text-slate-300">
                                            Ecommerce.pdf
                                            </span>
                                            <span class="block font-normal text-xs text-slate-500 mt-1">
                                            06 June 2021 / 155MB
                                            </span>
                                        </div>
                                    </div>
                                    <div class="flex-none">
                                        <button type="button" class="text-xs text-slate-900 dark:text-white">
                                        Download
                                        </button>
                                    </div>
                                </div>
                            </li>
                            <li class="block py-[8px]">
                                <div class="flex space-x-2 rtl:space-x-reverse">
                                    <div class="flex-1 flex space-x-2 rtl:space-x-reverse">
                                        <div class="flex-none">
                                            <div class="h-8 w-8">
                                                <img src="images/icon/zip-1.svg" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <span class="block text-slate-600 text-sm dark:text-slate-300">
                                            Job portal_app.zip
                                            </span>
                                            <span class="block font-normal text-xs text-slate-500 mt-1">
                                            06 June 2021 / 155MB
                                            </span>
                                        </div>
                                    </div>
                                    <div class="flex-none">
                                        <button type="button" class="text-xs text-slate-900 dark:text-white">
                                        Download
                                        </button>
                                    </div>
                                </div>
                            </li>
                            <li class="block py-[8px]">
                                <div class="flex space-x-2 rtl:space-x-reverse">
                                    <div class="flex-1 flex space-x-2 rtl:space-x-reverse">
                                        <div class="flex-none">
                                            <div class="h-8 w-8">
                                                <img src="images/icon/pdf-2.svg" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <span class="block text-slate-600 text-sm dark:text-slate-300">
                                            Ecommerce.pdf
                                            </span>
                                            <span class="block font-normal text-xs text-slate-500 mt-1">
                                            06 June 2021 / 155MB
                                            </span>
                                        </div>
                                    </div>
                                    <div class="flex-none">
                                        <button type="button" class="text-xs text-slate-900 dark:text-white">
                                        Download
                                        </button>
                                    </div>
                                </div>
                            </li>
                            <li class="block py-[8px]">
                                <div class="flex space-x-2 rtl:space-x-reverse">
                                    <div class="flex-1 flex space-x-2 rtl:space-x-reverse">
                                        <div class="flex-none">
                                            <div class="h-8 w-8">
                                                <img src="images/icon/scr-1.svg" alt="" class="block w-full h-full object-cover rounded-full border hover:border-white border-transparent">
                                            </div>
                                        </div>
                                        <div class="flex-1">
                                            <span class="block text-slate-600 text-sm dark:text-slate-300">
                                            Screenshot.jpg
                                            </span>
                                            <span class="block font-normal text-xs text-slate-500 mt-1">
                                            06 June 2021 / 155MB
                                            </span>
                                        </div>
                                    </div>
                                    <div class="flex-none">
                                        <button type="button" class="text-xs text-slate-900 dark:text-white">
                                        Download
                                        </button>
                                    </div>
                                </div>
                            </li>
                        </ul>
                        <!-- END: FIles Card -->
                  </div>
                </div>
              </div>
            </div>
        </div>
    </div>

    @push('scripts')
        <script type="module">
            const checkboxes = document.querySelectorAll('input[name="tasklist"]');
            // Add event listener to each checkbox
            checkboxes.forEach((checkbox) => {
                checkbox.addEventListener("change", function () {
                // Get parent list item
                const listItem = checkbox.closest("li");

                // Toggle class based on checkbox state
                if (checkbox.checked) {
                    listItem.classList.add("completed");
                } else {
                    listItem.classList.remove("completed");
                }
                });
            });
        </script>
    @endpush
</x-app-layout>
