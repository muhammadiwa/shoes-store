<x-app-layout>
    <div class="space-y-8">
        <div>
            <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-5">
            <div class="card">
                <header class="card-header">
                    <div class="card-title">Packages</div>
                </header>
                <div class="card-body p-6 space-y-5">
                    <div class="grid xl:grid-cols-4 md:grid-cols-2 grid-cols-1 gap-5">
                        <!-- START:: Advanced -->
                        <div
                            class="price-table bg-opacity-[0.16] dark:bg-opacity-[0.36] rounded-[6px] p-6 text-slate-900 dark:text-white relative overflow-hidden z-[1] bg-warning-500">
                            <div class="overlay absolute right-0 top-0 w-full h-full z-[-1]">
                                <img src="/images/all-img/big-shap1.png" alt="" class="ml-auto block">
                            </div>
                            <header class="mb-6">
                                <h4 class="text-xl mb-5">Advanced</h4>
                                <div class="space-x-4 relative flex items-center mb-5 rtl:space-x-reverse">
                                    <span class="text-[32px] leading-10 font-medium">
                                        $96
                                    </span>
                                    <span
                                        class="text-xs text-warning-500 font-medium px-3 py-1 rounded-full inline-block bg-white uppercase h-auto">Save
                                        20%</span>
                                </div>
                                <p class="text-slate-500 dark:text-slate-300 text-sm">
                                    per user/month, annually
                                </p>
                            </header>
                            <div class="price-body space-y-8">
                                <p class="text-sm leading-5 text-slate-600 dark:text-slate-300">
                                    Designed for teams who need to manage complex workflows with more automation and
                                    integration.
                                </p>
                                <div>
                                    <button class="btn-outline-dark dark:border-slate-400 w-full btn">Buy now</button>
                                </div>
                            </div>
                        </div>
                        <!-- END:: Advanced -->

                        <!-- START:: Business -->
                        <div
                            class="price-table bg-opacity-[0.16] dark:bg-opacity-[0.36] rounded-[6px] p-6 text-slate-900 dark:text-white relative overflow-hidden z-[1] bg-info-500">
                            <div class="overlay absolute right-0 top-0 w-full h-full z-[-1]">
                                <img src="images/all-img/big-shap2.png" alt="" class="ml-auto block">
                            </div>
                            <div
                                class="text-sm font-medium bg-slate-900 dark:bg-slate-900 text-white py-2 text-center absolute ltr:-right-[43px] rtl:-left-[43px] top-6 px-10 transform ltr:rotate-[45deg] rtl:-rotate-45">
                                Most popular
                            </div>
                            <header class="mb-6">
                                <h4 class="text-xl mb-5">Business</h4>
                                <div class="space-x-4 relative flex items-center mb-5 rtl:space-x-reverse">
                                    <span class="text-[32px] leading-10 font-medium">
                                        $196
                                    </span>
                                    <span
                                        class="text-xs text-warning-500 font-medium px-3 py-1 rounded-full inline-block bg-white uppercase h-auto">Save
                                        20%</span>
                                </div>
                                <p class="text-slate-500 dark:text-slate-300 text-sm">
                                    per user/month, annually
                                </p>
                            </header>
                            <div class="price-body space-y-8">
                                <p class="text-sm leading-5 text-slate-600 dark:text-slate-300">
                                    Designed for teams who need to manage complex workflows with more automation and
                                    integration.
                                </p>
                                <div>
                                    <button class="btn-outline-dark dark:border-slate-400 w-full btn">Buy now</button>
                                </div>
                            </div>
                        </div>
                        <!-- END:: Business -->

                        <!-- START:: Basic -->
                        <div
                            class="price-table bg-opacity-[0.16] dark:bg-opacity-[0.36] rounded-[6px] p-6 text-slate-900 dark:text-white relative overflow-hidden z-[1] bg-success-500">
                            <div class="overlay absolute right-0 top-0 w-full h-full z-[-1]">
                                <img src="images/all-img/big-shap3.png" alt="" class="ml-auto block">
                            </div>
                            <header class="mb-6">
                                <h4 class="text-xl mb-5">Basic</h4>
                                <div class="space-x-4 relative flex items-center mb-5 rtl:space-x-reverse">
                                    <span class="text-[32px] leading-10 font-medium">
                                        $26
                                    </span>
                                    <span
                                        class="text-xs text-warning-500 font-medium px-3 py-1 rounded-full inline-block bg-white uppercase h-auto">Save
                                        20%</span>
                                </div>
                                <p class="text-slate-500 dark:text-slate-300 text-sm">
                                    per user/month, annually
                                </p>
                            </header>
                            <div class="price-body space-y-8">
                                <p class="text-sm leading-5 text-slate-600 dark:text-slate-300">
                                    Designed for teams who need to manage complex workflows with more automation and
                                    integration.
                                </p>
                                <div>
                                    <button class="btn-outline-dark dark:border-slate-400 w-full btn">Try it
                                        free</button>
                                </div>
                            </div>
                        </div>
                        <!-- END:: Basic -->

                        <!-- START:: Advanced -->
                        <div
                            class="price-table bg-opacity-[0.16] dark:bg-opacity-[0.36] rounded-[6px] p-6 text-slate-900 dark:text-white relative overflow-hidden z-[1] bg-primary-500">
                            <div class="overlay absolute right-0 top-0 w-full h-full z-[-1]">
                                <img src="images/all-img/big-shap4.png" alt="" class="ml-auto block">
                            </div>
                            <header class="mb-6">
                                <h4 class="text-xl mb-5">Got a large team?</h4>
                                <div class="space-x-4 relative flex items-center mb-5 rtl:space-x-reverse">
                                    <span class="text-[32px] leading-10 font-medium">
                                        $96
                                    </span>
                                    <span
                                        class="text-xs text-warning-500 font-medium px-3 py-1 rounded-full inline-block bg-white uppercase h-auto">Save
                                        20%</span>
                                </div>
                                <p class="text-slate-500 dark:text-slate-300 text-sm">
                                    per user/month, annually
                                </p>
                            </header>
                            <div class="price-body space-y-8">
                                <p class="text-sm leading-5 text-slate-600 dark:text-slate-300">
                                    Designed for teams who need to manage complex workflows with more automation and
                                    integration.
                                </p>
                                <div>
                                    <button class="btn-outline-dark dark:border-slate-400 w-full btn">Request a
                                        quote</button>
                                </div>
                            </div>
                        </div>
                        <!-- END:: Got a large team? -->
                    </div>
                    <div class="grid xl:grid-cols-4 md:grid-cols-2 grid-cols-1 gap-5">
                        <!-- START:: Advanced -->
                        <div
                            class="price-table rounded-[6px] shadow-base dark:bg-slate-700 p-6 text-slate-900 dark:text-white relative overflow-hidden z-[1] bg-white">
                            <header class="mb-6">
                                <h4 class="text-xl mb-5 text-slate-900 dark:text-slate-300 ">
                                    Advanced
                                </h4>
                                <div
                                    class="space-x-4 relative flex items-center mb-5 rtl:space-x-reverse text-slate-900 dark:text-slate-300">
                                    <span class="text-[32px] leading-10 font-medium">
                                        $96
                                    </span>
                                    <span
                                        class="text-xs bg-warning-50 text-warning-500 font-medium px-2 py-1 rounded-full inline-block dark:bg-slate-800 uppercase h-auto">
                                        Save 20%</span>
                                </div>
                                <p class="text-sm text-slate-500 dark:text-slate-300">
                                    per user/month, annually
                                </p>
                            </header>
                            <div class="price-body space-y-8">
                                <p class=" text-sm leading-5 text-slate-600 dark:text-slate-300">
                                    Designed for teams who need to manage complex workflows with more automation and
                                    integration.
                                </p>
                                <div>
                                    <button class="w-full btn btn-outline-dark dark:border-slate-400"> Buy now
                                    </button>
                                </div>
                            </div>
                        </div>
                        <!-- END:: Advanced -->

                        <!-- START:: Busuness -->
                        <div
                            class="price-table rounded-[6px] shadow-base dark:bg-slate-900 p-6 dark:text-white relative overflow-hidden z-[1] bg-slate-900">
                            <div
                                class="text-sm font-medium bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-300 py-2 text-center absolute ltr:-right-[43px] rtl:-left-[43px] top-6 px-10 transform ltr:rotate-[45deg] rtl:-rotate-45">
                                Most Popular
                            </div>
                            <header class="mb-6">
                                <h4 class="text-xl mb-5 text-slate-100">
                                    Business
                                </h4>
                                <div
                                    class="space-x-4 relative flex items-center mb-5 rtl:space-x-revers text-slate-100">
                                    <span class="text-[32px] leading-10 font-medium">
                                        $96
                                    </span>
                                    <span
                                        class="text-xs bg-warning-50 text-warning-500 font-medium px-2 py-1 rounded-full inline-block dark:bg-slate-700 uppercase h-auto">
                                        Save 20%</span>
                                </div>
                                <p class="text-sm text-slate-100">
                                    per user/month, annually
                                </p>
                            </header>
                            <div class="price-body space-y-8">
                                <p class=" text-sm leading-5 text-slate-100 ">
                                    Designed for teams who need to manage complex workflows with more automation and
                                    integration.
                                </p>
                                <div>
                                    <button class="w-full btn text-slate-100 border-slate-300 border"> Buy now
                                    </button>
                                </div>
                            </div>
                        </div>
                        <!-- END:: Busuness -->

                        <!-- START:: Basic -->
                        <div
                            class="price-table rounded-[6px] shadow-base dark:bg-slate-700 p-6 text-slate-900 dark:text-white relative overflow-hidden z-[1] bg-white">
                            <header class="mb-6">
                                <h4 class="text-xl mb-5 text-slate-900 dark:text-slate-300 ">
                                    Basic
                                </h4>
                                <div
                                    class="space-x-4 relative flex items-center mb-5 rtl:space-x-reverse text-slate-900 dark:text-slate-300">
                                    <span class="text-[32px] leading-10 font-medium">
                                        $26
                                    </span>
                                    <span
                                        class="text-xs bg-warning-50 text-warning-500 font-medium px-2 py-1 rounded-full inline-block dark:bg-slate-800 uppercase h-auto">
                                        Save 20%</span>
                                </div>
                                <p class="text-sm text-slate-500 dark:text-slate-300">
                                    per user/month, annually
                                </p>
                            </header>
                            <div class="price-body space-y-8">
                                <p class=" text-sm leading-5 text-slate-600 dark:text-slate-300">
                                    Designed for teams who need to manage complex workflows with more automation and
                                    integration.
                                </p>
                                <div>
                                    <button class="w-full btn btn-outline-dark dark:border-slate-400"> Try it free
                                    </button>
                                </div>
                            </div>
                        </div>
                        <!-- END:: Basic -->

                        <!-- START:: Got a Large Team -->
                        <div
                            class="price-table rounded-[6px] shadow-base dark:bg-slate-700 p-6 text-slate-900 dark:text-white relative overflow-hidden z-[1] bg-white">
                            <header class="mb-6">
                                <h4 class="text-xl mb-5 text-slate-900 dark:text-slate-300 ">
                                    Got a large team?
                                </h4>
                                <div
                                    class="space-x-4 relative flex items-center mb-5 rtl:space-x-reverse text-slate-900 dark:text-slate-300">
                                    <span class="text-[32px] leading-10 font-medium">
                                        $96
                                    </span>
                                    <span
                                        class="text-xs bg-warning-50 text-warning-500 font-medium px-2 py-1 rounded-full inline-block dark:bg-slate-800 uppercase h-auto">
                                        Save 20%</span>
                                </div>
                                <p class="text-sm text-slate-500 dark:text-slate-300">
                                    per user/month, annually
                                </p>
                            </header>
                            <div class="price-body space-y-8">
                                <p class=" text-sm leading-5 text-slate-600 dark:text-slate-300">
                                    Designed for teams who need to manage complex workflows with more automation and
                                    integration.
                                </p>
                                <div>
                                    <button class="w-full btn btn-outline-dark dark:border-slate-400"> Request a quote
                                    </button>
                                </div>
                            </div>
                        </div>
                        <!-- END:: Got a Large Team -->
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
