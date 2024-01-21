<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid grid-cols-2 gap-6">
            <!-- BEGIN: Basic Badges -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Basic Badges</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-x-3"> <span class="badge bg-primary-500 text-white capitalize">primary</span> <span class="badge bg-secondary-500 text-white capitalize">secondary</span> <span class="badge bg-info-500 text-white capitalize">info</span> <span class="badge bg-success-500 text-white capitalize">success</span> <span class="badge bg-warning-500 text-white capitalize">warning</span> <span class="badge bg-danger-500 text-white capitalize">danger</span> <span class="badge bg-slate-900 text-white capitalize">dark</span> </div>
                </div>
            </div>
            <!-- END: Basic Badges -->
            <!-- BEGIN: Pill Badges -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Pill Badges</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-x-3"> <span class="badge bg-primary-500 text-white capitalize pill">primary</span> <span class="badge bg-secondary-500 text-white capitalize pill">secondary</span> <span class="badge bg-info-500 text-white capitalize pill">info</span> <span class="badge bg-success-500 text-white capitalize pill">success</span> <span class="badge bg-warning-500 text-white capitalize pill">warning</span> <span class="badge bg-danger-500 text-white capitalize pill">danger</span> <span class="badge bg-slate-900 text-white capitalize pill">dark</span> </div>
                </div>
            </div>
            <!-- END: Pill Badges -->
            <!-- BEGIN: Soft Badges -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Soft Badges</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-x-3"> <span class="badge bg-primary-500 text-primary-500 bg-opacity-30 capitalize">primary</span> <span class="badge bg-secondary-500 text-secondary-500 bg-opacity-30 capitalize">secondary</span> <span class="badge bg-info-500 text-info-500 bg-opacity-30 capitalize">info</span> <span class="badge bg-success-500 text-success-500 bg-opacity-30 capitalize">success</span> <span class="badge bg-warning-500 text-warning-500 bg-opacity-30 capitalize">warning</span> <span class="badge bg-danger-500 text-danger-500 bg-opacity-30 capitalize">danger</span> <span class="badge bg-slate-900 text-slate-900 dark:text-slate-200 bg-opacity-30 capitalize">dark</span> </div>
                </div>
            </div>
            <!-- END: Soft Badges -->
            <!-- BEGIN: Soft pill Badges -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Soft Pill Badges</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-x-3"> <span class="badge bg-primary-500 text-primary-500 bg-opacity-30 capitalize pill">primary</span> <span class="badge bg-secondary-500 text-secondary-500 bg-opacity-30 capitalize pill">secondary</span> <span class="badge bg-info-500 text-info-500 bg-opacity-30 capitalize pill">info</span> <span class="badge bg-success-500 text-success-500 bg-opacity-30 capitalize pill">success</span> <span class="badge bg-warning-500 text-warning-500 bg-opacity-30 capitalize pill">warning</span> <span class="badge bg-danger-500 text-danger-500 bg-opacity-30 capitalize pill">danger</span> <span class="badge bg-slate-900 text-slate-900 dark:text-slate-200 bg-opacity-30 capitalize pill">dark</span> </div>
                </div>
            </div>
            <!-- END: Soft pill Badges -->
            <!-- BEGIN: Badges With Icon -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Badges With Icon</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-x-3"> <span class="badge bg-primary-500 text-white capitalize inline-flex items-center">
                  <iconify-icon class="ltr:mr-1 rtl:ml-1" icon="heroicons-outline:star"></iconify-icon>
                  primary</span> <span class="badge bg-secondary-500 text-white capitalize inline-flex items-center">
                  <iconify-icon class="ltr:mr-1 rtl:ml-1" icon="heroicons-outline:star"></iconify-icon>
                  secondary</span> <span class="badge bg-info-500 text-white capitalize inline-flex items-center">
                  <iconify-icon class="ltr:mr-1 rtl:ml-1" icon="heroicons-outline:star"></iconify-icon>
                  info</span> <span class="badge bg-success-500 text-white capitalize inline-flex items-center">
                  <iconify-icon class="ltr:mr-1 rtl:ml-1" icon="heroicons-outline:star"></iconify-icon>
                  success</span> <span class="badge bg-warning-500 text-white capitalize inline-flex items-center">
                  <iconify-icon class="ltr:mr-1 rtl:ml-1" icon="heroicons-outline:star"></iconify-icon>
                  warning</span> <span class="badge bg-danger-500 text-white capitalize inline-flex items-center">
                  <iconify-icon class="ltr:mr-1 rtl:ml-1" icon="heroicons-outline:star"></iconify-icon>
                  danger</span> <span class="badge bg-slate-900 text-white capitalize inline-flex items-center">
                <iconify-icon class="ltr:mr-1 rtl:ml-1" icon="heroicons-outline:star"></iconify-icon>
                dark</span> </div>
                </div>
            </div>
            <!-- END: Badges with Icon -->
            <!-- BEGIN: Badges With Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Badges In Buttons</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-x-5">
                        <button class="btn inline-flex justify-center btn-dark">Notification <span class="w-5 h-5 inline-flex items-center justify-center bg-white text-slate-900 rounded-md font-Inter text-xs ltr:ml-1
                                    rtl:mr-1 relative top-[2px]">
                  2</span> </button>
                        <button class="btn inline-flex justify-center btn-success">Message <span class="w-5 h-5 inline-flex items-center justify-center bg-white text-slate-900 rounded-md font-Inter text-xs ltr:ml-1
                                    rtl:mr-1 relative top-[2px]">
                  2</span> </button>
                        <button class="btn inline-flex justify-center btn-info">Draft <span class="w-5 h-5 inline-flex items-center justify-center bg-white text-slate-900 rounded-md font-Inter text-xs ltr:ml-1
                                    rtl:mr-1 relative top-[2px]">
                  2</span> </button>
                    </div>
                </div>
            </div>
            <!-- END: Badges With Buttons -->
            <!-- BEGIN: Badges In Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Badges In Buttons</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-x-5">
                        <button class="btn relative inline-flex justify-center btn-dark">Mails <span class="w-5 h-5 inline-flex items-center justify-center bg-danger-500 text-white rounded-full font-Inter text-xs absolute -top-[5px] -right-1">
                  2</span> </button>
                        <button class="btn relative inline-flex justify-center btn-success">Message <span class="w-5 h-5 inline-flex items-center justify-center bg-danger-500 text-white rounded-full font-Inter text-xs absolute -top-[5px] -right-1">
                  0</span> </button>
                        <button class="btn relative inline-flex justify-center btn-info">Draft <span class="w-5 h-5 inline-flex items-center justify-center bg-danger-500 text-white rounded-full font-Inter text-xs absolute -top-[5px] -right-1">
                  1</span> </button>
                    </div>
                </div>
            </div>
            <!-- END: Badges In Buttons -->
        </div>
    </div>
</x-app-layout>
