<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <!-- Theme Color Alerts -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Theme Color Alerts</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="alert alert-dark">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-primary">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-secondary">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-info">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-success">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-warning">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-danger">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Light Color Alerts -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Light Color Alerts</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="alert alert-dark light-mode">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-primary light-mode">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-secondary light-mode">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-info light-mode">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-success light-mode">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-warning light-mode">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-danger light-mode">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1"> This is an alert—check it out! </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Linked Color Alerts -->
            <div class="xl:col-span-2 col-span-1">
                <div class="card">
                    <div class="card-body flex flex-col p-6">
                        <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                            <div class="flex-1">
                                <div class="card-title text-slate-900 dark:text-white">Link Colors</div>
                            </div>
                        </header>
                        <div class="card-text h-full ">
                            <div class="space-y-5">
                                <div class="alert alert-dark light-mode">
                                    <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                        <div class="flex-1"> This is an alert with <a aria-current="page" href="/app/alert#" class="router-link-active router-link-exact-active underline text-slate-900 dark:text-slate-300 text-sm font-medium">an example link</a>. Check it out! </div>
                                    </div>
                                </div>
                                <div class="alert alert-primary light-mode">
                                    <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                        <div class="flex-1"> This is an alert with <a aria-current="page" href="/app/alert#" class="router-link-active router-link-exact-active underline text-alert-primary-900 dark:text-slate-300 text-sm font-medium">
                                          an example link</a>. Check it out! </div>
                                    </div>
                                </div>
                                <div class="alert alert-secondary light-mode">
                                    <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                        <div class="flex-1"> This is an alert with <a aria-current="page" href="/app/alert#" class="router-link-active router-link-exact-active underline text-alert-secondary-900 dark:text-slate-300 text-sm font-medium">
                                          an example link</a>. Check it out! </div>
                                    </div>
                                </div>
                                <div class="alert alert-info light-mode">
                                    <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                        <div class="flex-1"> This is an alert with <a aria-current="page" href="/app/alert#" class="router-link-active router-link-exact-active underline text-alert-info-900 dark:text-slate-300 text-sm font-medium">
                                          an example link</a>. Check it out! </div>
                                    </div>
                                </div>
                                <div class="alert alert-success light-mode">
                                    <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                        <div class="flex-1"> This is an alert with <a aria-current="page" href="/app/alert#" class="router-link-active router-link-exact-active underline text-alert-success-900 dark:text-slate-300 text-sm font-medium">
                                          an example link</a>. Check it out! </div>
                                    </div>
                                </div>
                                <div class="alert alert-warning light-mode">
                                    <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                        <div class="flex-1"> This is an alert with <a aria-current="page" href="/app/alert#" class="router-link-active router-link-exact-active underline text-alert-warning-900 dark:text-slate-300 text-sm font-medium">
                                          an example link</a>. Check it out! </div>
                                    </div>
                                </div>
                                <div class="alert alert-danger light-mode">
                                    <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                        <div class="flex-1"> This is an alert with <a aria-current="page" href="/app/alert#" class="router-link-active router-link-exact-active underline text-alert-danger-900 dark:text-slate-300 text-sm font-medium">
                                          an example link</a>. Check it out! </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Dismissible Theme Color Alerts With Icon -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Dismissible Theme Color Alerts With Icon</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="alert alert-dark">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-primary">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-secondary">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-info">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-success">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-warning">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-danger">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Dismissible Theme Color Alerts With Icon -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Dismissible Theme Color Alerts With Icon</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="alert alert-dark light-mode ">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-primary light-mode">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-secondary light-mode">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-info light-mode">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-success light-mode">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-warning light-mode">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-danger light-mode">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close" class="relative top-[4px]"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Outline Theme Color Alerts -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Outline Theme Color Alerts</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="alert alert-outline-dark ">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1 font-Inter"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-outline-primary">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1 font-Inter"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-outline-secondary">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1 font-Inter"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-outline-info">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1 font-Inter"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-outline-success">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1 font-Inter"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-outline-warning">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1 font-Inter"> This is an alert—check it out! </div>
                                </div>
                            </div>
                            <div class="alert alert-outline-danger">
                                <div class="flex items-start space-x-3 rtl:space-x-reverse">
                                    <div class="flex-1 font-Inter"> This is an alert—check it out! </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Outline Light Color Alerts With Icon -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Outline Light Color Alerts With Icon</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-5">
                            <div class="py-[18px] px-6 font-normal text-sm rounded-md bg-white text-slate-800 dark:text-slate-300 border border-slate-800
                                        dark:border-slate-600 dark:bg-slate-800">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="py-[18px] px-6 font-normal text-sm rounded-md bg-white text-primary-500 border border-primary-500
                                            dark:bg-slate-800">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="py-[18px] px-6 font-normal text-sm rounded-md bg-white text-secondary-500 border border-secondary-500
                                            dark:bg-slate-800">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="py-[18px] px-6 font-normal text-sm rounded-md bg-white text-info-500 border border-info-500
                                            dark:bg-slate-800">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="py-[18px] px-6 font-normal text-sm rounded-md bg-white text-success-500 border border-success-500
                                            dark:bg-slate-800">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="py-[18px] px-6 font-normal text-sm rounded-md bg-white text-warning-500 border border-warning-500
                                            dark:bg-slate-800">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
                                    </div>
                                </div>
                            </div>
                            <div class="py-[18px] px-6 font-normal text-sm rounded-md bg-white text-danger-500 border border-danger-500
                                            dark:bg-slate-800">
                                <div class="flex items-center space-x-3 rtl:space-x-reverse">
                                    <iconify-icon class="text-2xl flex-0" icon="system-uicons:target"></iconify-icon>
                                    <p class="flex-1 font-Inter"> This is an alert—check it out! </p>
                                    <div class="flex-0 text-xl cursor-pointer">
                                        <iconify-icon icon="line-md:close"></iconify-icon>
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
