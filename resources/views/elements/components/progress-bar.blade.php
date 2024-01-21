<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <!-- BEGIN: Basic Progress Bar -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Default Examples</div>
                    </div>
                </header>
                <div class="card-text h-full space-y-10">
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="progress-bar bg-black-900 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="progress-bar2 bg-black-900 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="progress-bar3 bg-black-900 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="progress-bar4 bg-black-900 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="progress-bar5 bg-black-900 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                </div>
                </div>
            </div>
            <!-- END: Basic Progress Bar -->

            <!-- BEGIN: Background Color Progress Bar -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Background Examples</div>
                    </div>
                </header>
                <div class="card-text h-full space-y-10">
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="bg-info-500 progress-bar2 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="bg-success-500 progress-bar3 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="bg-warning-500 progress-bar4 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                    <div class="bg-danger-500 progress-bar5 h-full rounded-xl" style="width: 0%"></div>
                    </div>
                </div>
                </div>
            </div>
            <!-- END: Background Color Progress Bar -->

            <!-- BEGIN: Height Progress Bar -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Height Examples</div>
                    </div>
                </header>
                <div class="card-text h-full space-y-10">
                    <div>
                    <h6 class="block text-slate-500 font-medium text-lg tracking-[0.01em] mb-2">Progress sm</h6>
                    <div class="w-full bg-slate-200 h-1 rounded-xl overflow-hidden">
                        <div class="bg-primary-500 h-full rounded-xl" style="width: 45%"></div>
                    </div>
                    </div>
                    <div>
                    <h6 class="block text-slate-500 font-medium text-lg tracking-[0.01em] mb-2">Progress md</h6>
                    <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                        <div class="bg-success-500 h-full rounded-xl" style="width: 55%"></div>
                    </div>
                    </div>
                    <div>
                    <h6 class="block text-slate-500 font-medium text-lg tracking-[0.01em] mb-2">Progress lg</h6>
                    <div class="w-full bg-slate-200 h-3 rounded-xl overflow-hidden">
                        <div class="bg-warning-500 h-full rounded-xl" style="width: 65%"></div>
                    </div>
                    </div>
                    <div>
                    <h6 class="block text-slate-500 font-medium text-lg tracking-[0.01em] mb-2">Progress xl</h6>
                    <div class="w-full bg-slate-200 h-4 rounded-xl overflow-hidden">
                        <div class="bg-danger-500 h-full rounded-xl" style="width: 85%"></div>
                    </div>
                    </div>
                </div>
                </div>
            </div>
            <!-- END: Height Progress Bar -->

            <!-- BEGIN: Label Progress Bar -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Label Examples</div>
                    </div>
                </header>
                <div class="card-text h-full space-y-10">
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-primary-500 progress-bar rounded-xl flex items-center justify-center text-white font-Inter font-bold
                                            text-[10px]" style="width: 0%">40%</div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-info-500 stiped-bar progress-bar2 rounded-xl flex items-center justify-center text-white font-Inter
                                            font-bold text-[10px]" style="width: 0%">50%</div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-success-500 progress-bar3 rounded-xl flex items-center justify-center text-white font-Inter font-bold
                                            text-[10px]" style="width: 0%">60%</div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-warning-500 stiped-bar progress-bar4 rounded-xl flex items-center justify-center text-white font-Inter
                                            font-bold text-[10px]" style="width: 0%">75%</div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-danger-500 progress-bar5 rounded-xl flex items-center justify-center text-white font-Inter font-bold
                                            text-[10px]" style="width: 0%">95%</div>
                    </div>
                </div>
                </div>
            </div>
            <!-- END: Label Progress Bar -->

            <!-- BEGIN: Multiple Progress Bar -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Multiple Bar Examples</div>
                    </div>
                </header>
                <div class="card-text h-full space-y-10">
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden flex items-center">
                    <div class=" h-full bg-primary-500 stiped-bar progress-bar flex items-center justify-center text-white font-Inter font-bold
                                            text-[10px]" style="width: 0%">40%</div>
                    <div class=" h-full bg-info-500 stiped-bar progress-bar2 rounded-r-2xl flex items-center justify-center text-white font-Inter
                                            font-bold text-[10px]" style="width: 0%">50%</div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden flex items-center">
                    <div class=" h-full bg-primary-500 stiped-bar progress-bar6 flex items-center justify-center text-white font-Inter font-bold
                                            text-[10px]" style="width: 0%">25%</div>
                    <div class=" h-full bg-success-500 stiped-bar progress-bar6 flex items-center justify-center text-white font-Inter font-bold
                                            text-[10px]" style="width: 0%">25%</div>
                    <div class=" h-full bg-danger-500 stiped-bar progress-bar6 rounded-r-xl flex items-center justify-center text-white font-Inter
                                            font-bold text-[10px]" style="width: 0%">25%</div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden flex items-center">
                    <div class=" h-full bg-primary-500 progress-bar6 flex items-center justify-center text-white font-Inter font-bold text-[10px]" style="width: 0%">25%</div>
                    <div class=" h-full bg-success-500 progress-bar flex items-center justify-center text-white font-Inter font-bold text-[10px]" style="width: 0%">40%</div>
                    <div class=" h-full bg-danger-500 progress-bar6 rounded-r-xl flex items-center justify-center text-white font-Inter font-bold
                                            text-[10px]" style="width: 0%">25%</div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden flex items-center">
                    <div class=" h-full bg-primary-500 stiped-bar progress-bar6 flex items-center justify-center text-white font-Inter font-bold
                                            text-[10px]" style="width: 0%">25%</div>
                    <div class=" h-full bg-success-500 progress-bar flex items-center justify-center text-white font-Inter font-bold text-[10px]" style="width: 0%">40%</div>
                    <div class=" h-full bg-danger-500 stiped-bar progress-bar6 rounded-r-xl flex items-center justify-center text-white font-Inter
                                            font-bold text-[10px]" style="width: 0%">25%</div>
                    </div>
                </div>
                </div>
            </div>
            <!-- END: Multiple Progress Bar -->


            <!-- BEGIN: Step Progress Bar -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Step Progress Bar Examples</div>
                    </div>
                </header>
                <div class="card-text h-full space-y-10">
                    <div class="relative m-5">
                    <div class="line w-full h-1 bg-slate-200 absolute left-0 top-1/2 -translate-y-1/2"></div>
                    <p class="step w-1/2 h-1 rounded-xl bg-primary-500 absolute left-0 top-1/2 -translate-y-1/2 m-0 p-0"></p>
                    <div class="w-full relative z-20 flex items-center justify-between">
                        <span class="w-12 h-12 rounded-full border border-white bg-primary-500 text-white font-Inter font-semibold inline-flex
                                            items-center justify-center outline outline-offset-2 outline-primary-500">
                        1</span>
                        <span class="w-12 h-12 rounded-full border border-white bg-primary-500 text-white font-Inter font-semibold inline-flex
                                            items-center justify-center outline outline-offset-2 outline-primary-500">
                        2</span>
                        <span class="w-12 h-12 rounded-full border border-white bg-primary-500 text-white font-Inter font-semibold inline-flex
                                            items-center justify-center outline outline-offset-2 outline-primary-500">
                        3</span>
                    </div>
                    </div>
                    <div class="space-x-3 mx-5">
                    <button class="prev py-3 px-5 bg-primary-500 rounded-lg text-base font-Inter font-medium text-white">Prev</button>
                    <button class="next py-3 px-5 bg-primary-500 rounded-lg text-base font-Inter font-medium text-white">Next</button>
                    </div>
                </div>
                </div>
            </div>
            <!-- END: Step Progress Bar -->

            <!-- BEGIN: Striped Animations Progress Bar -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Striped Animation Examples</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-10">
                        <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                            <div class=" h-full bg-primary-500 stiped-bar animated-strip progress-bar rounded-xl" style="width: 0%"></div>
                        </div>
                        <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                            <div class=" h-full bg-info-500 stiped-bar animated-strip progress-bar2 rounded-xl" style="width: 0%"></div>
                        </div>
                        <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                            <div class=" h-full bg-success-500 stiped-bar animated-strip progress-bar3 rounded-xl" style="width: 0%"></div>
                        </div>
                        <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                            <div class=" h-full bg-warning-500 stiped-bar animated-strip progress-bar4 rounded-xl" style="width: 0%"></div>
                        </div>
                        <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                            <div class=" h-full bg-danger-500 stiped-bar animated-strip progress-bar5 rounded-xl" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Striped Animations Progress Bar -->

            <!-- BEGIN: Striped Progress Bar -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Striped Examples</div>
                    </div>
                </header>
                <div class="card-text h-full space-y-10">
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-primary-500 stiped-bar progress-bar rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-info-500 stiped-bar progress-bar2 rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-success-500 stiped-bar progress-bar3 rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-warning-500 stiped-bar progress-bar4 rounded-xl" style="width: 0%"></div>
                    </div>
                    <div class="w-full  bg-slate-200 h-3 rounded-xl overflow-hidden">
                    <div class=" h-full bg-danger-500 stiped-bar progress-bar5 rounded-xl" style="width: 0%"></div>
                    </div>
                </div>
                </div>
            </div>
            <!-- END: Striped Progress Bar -->
        </div>
    </div>
</x-app-layout>
