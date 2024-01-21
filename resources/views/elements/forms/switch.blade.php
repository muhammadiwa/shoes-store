<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-6">

            <div class="card">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Basic Switch</div>
                  </div>
                </header>
                <div class="card-text h-full space-y-4">
                  <div class="flex items-center space-x-7 flex-wrap">
                    <div class="flex items-center space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="checked" class="sr-only peer">
                        <span class="w-11 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-black-500"></span>
                      </label>
                      <span class="text-sm text-slate-600 font-Inter font-normal">Active Switch</span>

                    </div>
                    <div class="flex items-center space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" class="sr-only peer">
                        <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-black-500"></div>
                      </label>
                      <span class="text-sm text-slate-600 font-Inter font-normal">Inactive Switch</span>

                    </div>
                    <div class="flex items-center space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" disabled="disabled" class="sr-only peer cursor-not-allowed opacity-50">
                        <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none cursor-not-allowed ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-black-500 opacity-50"></div>
                      </label>
                      <span class="text-sm text-slate-600 font-Inter font-normal opacity-50">Diasbaled</span>

                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Theme Switch</div>
                  </div>
                </header>
                <div class="card-text h-full space-y-4">
                  <div class="flex items-center flex-wrap">


                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-500"></div>
                      </label>
                      <span class="text-sm text-primary-600 font-Inter font-normal capitalize">primary</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-secondary-500"></div>
                      </label>
                      <span class="text-sm text-secondary-600 font-Inter font-normal capitalize">secondary</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-info-500"></div>
                      </label>
                      <span class="text-sm text-info-600 font-Inter font-normal capitalize">info</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-success-500"></div>
                      </label>
                      <span class="text-sm text-success-600 font-Inter font-normal capitalize">success</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-warning-500"></div>
                      </label>
                      <span class="text-sm text-warning-600 font-Inter font-normal capitalize">warning</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-danger-500"></div>
                      </label>
                      <span class="text-sm text-danger-600 font-Inter font-normal capitalize">danger</span>
                    </div>

                  </div>
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Switch With Badge</div>
                  </div>
                </header>
                <div class="card-text h-full space-y-4">
                  <div class="flex items-center flex-wrap">


                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-500"></div>
                        <span class="absolute left-1 z-20 text-xs text-white font-Inter font-normal opacity-0 peer-checked:opacity-100">On</span>
                        <span class="absolute right-1 z-20 text-xs text-white font-Inter font-normal opacity-100 peer-checked:opacity-0">Off</span>
                      </label>
                      <span class="text-sm text-primary-600 font-Inter font-normal capitalize">primary</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-secondary-500"></div>
                        <span class="absolute left-1 z-20 text-xs text-white font-Inter font-normal opacity-0 peer-checked:opacity-100">On</span>
                        <span class="absolute right-1 z-20 text-xs text-white font-Inter font-normal opacity-100 peer-checked:opacity-0">Off</span>
                      </label>
                      <span class="text-sm text-secondary-600 font-Inter font-normal capitalize">secondary</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-info-500"></div>
                        <span class="absolute left-1 z-20 text-xs text-white font-Inter font-normal opacity-0 peer-checked:opacity-100">On</span>
                        <span class="absolute right-1 z-20 text-xs text-white font-Inter font-normal opacity-100 peer-checked:opacity-0">Off</span>
                      </label>
                      <span class="text-sm text-info-600 font-Inter font-normal capitalize">info</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-success-500"></div>
                        <span class="absolute left-1 z-20 text-xs text-white font-Inter font-normal opacity-0 peer-checked:opacity-100">On</span>
                        <span class="absolute right-1 z-20 text-xs text-white font-Inter font-normal opacity-100 peer-checked:opacity-0">Off</span>
                      </label>
                      <span class="text-sm text-success-600 font-Inter font-normal capitalize">success</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-warning-500"></div>
                        <span class="absolute left-1 z-20 text-xs text-white font-Inter font-normal opacity-0 peer-checked:opacity-100">On</span>
                        <span class="absolute right-1 z-20 text-xs text-white font-Inter font-normal opacity-100 peer-checked:opacity-0">Off</span>
                      </label>
                      <span class="text-sm text-warning-600 font-Inter font-normal capitalize">warning</span>
                    </div>

                    <div class="flex items-center mr-2 sm:mr-4 mt-2 space-x-2">
                      <label class="relative inline-flex h-6 w-[46px] items-center rounded-full transition-all duration-150 cursor-pointer">
                        <input type="checkbox" value="" checked="" class="sr-only peer">
                        <div class="w-14 h-6 bg-gray-200 peer-focus:outline-none ring-0 rounded-full peer dark:bg-gray-900 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:z-10 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-danger-500"></div>
                        <span class="absolute left-1 z-20 text-xs text-white font-Inter font-normal opacity-0 peer-checked:opacity-100">On</span>
                        <span class="absolute right-1 z-20 text-xs text-white font-Inter font-normal opacity-100 peer-checked:opacity-0">Off</span>
                      </label>
                      <span class="text-sm text-danger-600 font-Inter font-normal capitalize">danger</span>
                    </div>

                  </div>
                </div>
              </div>
            </div>

          </div>
    </div>
</x-app-layout>
