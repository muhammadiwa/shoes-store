<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="card rounded-md bg-white dark:bg-slate-800 lg:h-full shadow-base">
            <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                        <div class="card-title text-slate-900 dark:text-white">All Colors</div>
                    </div>
                </header>
                <div class="card-text h-full">
                    <div class="space-y-5">
                        <div class="col-span-2 text-base font-medium text-slate-900 dark:text-slate-300 mb-6">Bases</div>
                        <div class="flex flex-wrap colors_parent">
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-900 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 text-sm my-1 pt-1 dark:text-slate-300">Dark</p>
                                <p class="flex-0 text-sm dark:text-slate-300">#0F172A</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-white border-gray-500 border rounded-md flex flex-col text-slate-900 p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 text-sm my-1 pt-1 dark:text-slate-300"> White </p>
                                <p class="flex-0 text-sm dark:text-slate-300">#FFFFFF</p>
                            </div>
                        </div>
                        <!-- Slate -->
                        <div class="col-span-2 text-base font-medium text-slate-900 dark:text-slate-300 mb-6">Slate</div>
                        <div class="flex flex-wrap colors_parent">
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-50 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-50 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#f8fafc</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-100 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-100 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#f1f5f9</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-200 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-200 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#e2e8f0</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-300 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-300 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#cbd5e1</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-400 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-400 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#94a3b8</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-500 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-500 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#64748b</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-600 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-600 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#475569</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-700 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-700 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#1e293b</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-800 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-800 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#1e293b</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-slate-900 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> slate-900 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#0f172a</p>
                            </div>
                        </div>
                        <!-- Primary -->
                        <div class="col-span-2 text-base font-medium text-slate-900 dark:text-slate-300 mb-6">Primary</div>
                        <div class="flex flex-wrap colors_parent">
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-50 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-50 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#F6F8FF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-100 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-100 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#EDF0FF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-200 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-200 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#D1DAFE</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-300 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-300 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#B4C2FD</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-400 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-400 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#8092FF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-500 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-500 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#7E96FC</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-600 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-600 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#3F5EDF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-700 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-700 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#2A3F96</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-800 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-800 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#203071</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-primary-900 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> primary-900 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#151F49</p>
                            </div>
                        </div>
                        <!-- Info -->
                        <div class="col-span-2 text-base font-medium text-slate-900 dark:text-slate-300 mb-6">Info</div>
                        <div class="flex flex-wrap colors_parent">
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-50 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-50 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#F3FEFF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-100 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-100 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#E7FEFF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-200 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-200 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#C5FDFF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-300 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-300 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#A3FCFF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-400 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-400 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#5FF9FF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-500 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-500 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#0CE7FA</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-600 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-600 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#00B8D4</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-700 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-700 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#007A8D</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-800 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-800 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#005E67</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-info-900 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> info-900 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#003F42</p>
                            </div>
                        </div>
                        <!-- Success -->
                        <div class="col-span-2 text-base font-medium text-slate-900 dark:text-slate-300 mb-6">Success</div>
                        <div class="flex flex-wrap colors_parent">
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-50 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-50 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#F3FEF8</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-100 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-100 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#E7FDF1</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-200 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-200 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#E7FDF1</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-300 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-300 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#A3F9D5</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-400 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-400 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#5FF5B1</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-500 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-500 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#50C793</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-600 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-600 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#3F9A7A</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-700 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-700 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#2E6D61</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-800 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-800 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#1F4B47</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-success-900 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> success-900 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#0F2A2E</p>
                            </div>
                        </div>
                        <!-- Warning -->
                        <div class="col-span-2 text-base font-medium text-slate-900 dark:text-slate-300 mb-6">Warning</div>
                        <div class="flex flex-wrap colors_parent">
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-50 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-50 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FFFAF8</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-100 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-100 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FFF4F1</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-200 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-200 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FEE4DA</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-300 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-300 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FDD2C3</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-400 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-400 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FCB298</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-500 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-500 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FA916B</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-600 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-600 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#DF8260</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-700 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-700 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#965741</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-800 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-800 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#714231</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-warning-900 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> warning-900 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#4A2E21</p>
                            </div>
                        </div>
                        <!-- Danger -->
                        <div class="col-span-2 text-base font-medium text-slate-900 dark:text-slate-300 mb-6">Danger</div>
                        <div class="flex flex-wrap colors_parent">
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-50 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-50 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FFF7F7</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-100 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-100 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FEEFEF</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-200 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-200 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FCD6D7</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-300 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-300 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#FABBBD</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-400 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-400 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#F68B8D</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-500 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-500 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#F1595C</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-600 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-600 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#D75052</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-700 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-700 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#913638</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-800 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-800 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#6D292A</p>
                            </div>
                            <div>
                                <div class="color-box h-[96px] 2xl:w-[107px] w-[96px] bg-danger-900 rounded-md flex flex-col text-white p-4 transition-all duration-200 hover:shadow-sm hover:-translate-y-1"></div>
                                <p class="flex-1 font-Inter text-sm my-1 pt-1 dark:text-slate-300"> danger-900 </p>
                                <p class="flex-0 font-Inter text-sm dark:text-slate-300">#461A1B</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
