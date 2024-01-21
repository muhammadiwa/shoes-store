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
                            <div class="card-title text-slate-900 dark:text-white">Example One</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="grid grid-cols-3 gap-6">
                            <div class="bg-white dark:bg-slate-900 shadow rounded-md p-4 w-full mx-auto">
                                <div class="animate-pulse">
                                    <div class="flex items-center justify-between space-x-4 mb-7">
                                        <div class="w-10 h-10 rounded-md bg-slate-200"></div>
                                        <div class="w-full max-w-[350px] h-2 rounded-md bg-slate-200"></div>
                                        <div class="w-6 h-6 rounded-full bg-slate-200 inline-block"></div>
                                    </div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="grid grid-cols-2 gap-6">
                                        <div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                        </div>
                                        <div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                        </div>
                                    </div>
                                    <div class="grid grid-cols-2 gap-6 mt-4">
                                        <div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200"></div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200 -ml-3"></div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200 -ml-3"></div>
                                        </div>
                                        <div>
                                            <div class="w-1/2 h-7 rounded-full bg-slate-200"></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-white dark:bg-slate-900 shadow rounded-md p-4 w-full mx-auto">
                                <div class="animate-pulse">
                                    <div class="flex items-center justify-between space-x-4 mb-7">
                                        <div class="w-10 h-10 rounded-md bg-slate-200"></div>
                                        <div class="w-full max-w-[350px] h-2 rounded-md bg-slate-200"></div>
                                        <div class="w-6 h-6 rounded-full bg-slate-200 inline-block"></div>
                                    </div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="grid grid-cols-2 gap-6">
                                        <div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                        </div>
                                        <div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                        </div>
                                    </div>
                                    <div class="grid grid-cols-2 gap-6 mt-4">
                                        <div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200"></div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200 -ml-3"></div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200 -ml-3"></div>
                                        </div>
                                        <div>
                                            <div class="w-1/2 h-7 rounded-full bg-slate-200"></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-white dark:bg-slate-900 shadow rounded-md p-4 w-full mx-auto">
                                <div class="animate-pulse">
                                    <div class="flex items-center justify-between space-x-4 mb-7">
                                        <div class="w-10 h-10 rounded-md bg-slate-200"></div>
                                        <div class="w-full max-w-[350px] h-2 rounded-md bg-slate-200"></div>
                                        <div class="w-6 h-6 rounded-full bg-slate-200 inline-block"></div>
                                    </div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                    <div class="grid grid-cols-2 gap-6">
                                        <div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                        </div>
                                        <div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                            <div class="w-full h-2 rounded-sm bg-slate-200 my-3"></div>
                                        </div>
                                    </div>
                                    <div class="grid grid-cols-2 gap-6 mt-4">
                                        <div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200"></div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200 -ml-3"></div>
                                            <div class="w-7 h-7 rounded-full inline-block bg-slate-200 -ml-3"></div>
                                        </div>
                                        <div>
                                            <div class="w-1/2 h-7 rounded-full bg-slate-200"></div>
                                        </div>
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
                            <div class="card-title text-slate-900 dark:text-white">Example Two</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="bg-white dark:bg-slate-900 shadow rounded-md p-4 w-full mx-auto">
                            <div class="animate-pulse space-y-4">
                                <div class="flex items-center justify-between space-x-4 rtl:space-x-4-reverse mb-7">
                                    <div class="w-6 h-6 rounded-md bg-slate-200"></div>
                                    <div class="w-6 h-6 rounded-md bg-slate-200"></div>
                                    <div class="w-10 h-10 rounded-full bg-slate-200 inline-block"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                </div>
                                <div class="flex items-center justify-between space-x-4 mb-4">
                                    <div class="w-6 h-6 rounded-md bg-slate-200"></div>
                                    <div class="w-6 h-6 rounded-md bg-slate-200"></div>
                                    <div class="w-10 h-10 rounded-full bg-slate-200 inline-block"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                </div>
                                <div class="flex items-center justify-between space-x-4 mb-4">
                                    <div class="w-6 h-6 rounded-md bg-slate-200"></div>
                                    <div class="w-6 h-6 rounded-md bg-slate-200"></div>
                                    <div class="w-10 h-10 rounded-full bg-slate-200 inline-block"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
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
                            <div class="card-title text-slate-900 dark:text-white">Example Three</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="animate-pulse">
                            <div class="grid lg:grid-cols-5 md:grid-cols-3 sm:grid-cols-2 grid-cols-1 gap-6">
                                <div class="space-y-4">
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                </div>
                                <div class="space-y-4">
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                </div>
                                <div class="space-y-4">
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                </div>
                                <div class="space-y-4">
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                </div>
                                <div class="space-y-4">
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                    <div class="w-full h-2 rounded-md bg-slate-200"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
