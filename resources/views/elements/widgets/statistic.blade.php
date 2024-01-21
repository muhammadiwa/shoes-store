<x-app-layout>
    <div class="space-y-8">
        <div>
            <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-5">

            <!-- START::GROUP CHART 1 -->
            <div class="grid md:grid-cols-3 sm:grid-cols-2 grid-cols-1 gap-4">
                <!-- Totel revenue -->
                <div class="card">
                    <div class="card-body pt-4 pb-3 px-4">
                        <div class="flex space-x-3 rtl:space-x-reverse">
                            <div class="flex-none">
                                <div
                                    class="h-12 w-12 rounded-full flex flex-col items-center justify-center text-2xl bg-[#E5F9FF] dark:bg-slate-900 text-info-500">
                                    <iconify-icon icon="heroicons:shopping-cart"></iconify-icon>
                                </div>
                            </div>
                            <div class="flex-1">
                                <div class="text-slate-600 dark:text-slate-300 text-sm mb-1 font-medium">
                                    {{ __('Totel revenue') }}
                                </div>
                                <div class="text-slate-900 dark:text-white text-lg font-medium">
                                    3,564
                                </div>
                            </div>
                        </div>
                        <div class="ltr:ml-auto rtl:mr-auto max-w-[124px]">
                            <div id="spae-line1"></div>
                        </div>
                    </div>
                </div>

                <!-- Totel revenue -->
                <div class="card">
                    <div class="card-body pt-4 pb-3 px-4">
                        <div class="flex space-x-3 rtl:space-x-reverse">
                            <div class="flex-none">
                                <div
                                    class="h-12 w-12 rounded-full flex flex-col items-center justify-center text-2xl bg-[#FFEDE6] dark:bg-slate-900 text-warning-500">
                                    <iconify-icon icon="heroicons:cube"></iconify-icon>
                                </div>
                            </div>
                            <div class="flex-1">
                                <div class="text-slate-600 dark:text-slate-300 text-sm mb-1 font-medium">
                                    {{ __('Products sold') }}
                                </div>
                                <div class="text-slate-900 dark:text-white text-lg font-medium">
                                    564
                                </div>
                            </div>
                        </div>
                        <div class="ltr:ml-auto rtl:mr-auto max-w-[124px]">
                            <div id="spae-line2"></div>
                        </div>
                    </div>
                </div>

                <!-- Growth -->
                <div class="card">
                    <div class="card-body pt-4 pb-3 px-4">
                        <div class="flex space-x-3 rtl:space-x-reverse">
                            <div class="flex-none">
                                <div
                                    class="h-12 w-12 rounded-full flex flex-col items-center justify-center text-2xl bg-[#EAE6FF] dark:bg-slate-900 text-[#5743BE]">
                                    <iconify-icon icon="heroicons:arrow-trending-up-solid"></iconify-icon>
                                </div>
                            </div>
                            <div class="flex-1">
                                <div class="text-slate-600 dark:text-slate-300 text-sm mb-1 font-medium">
                                    {{ __('Growth') }}
                                </div>
                                <div class="text-slate-900 dark:text-white text-lg font-medium">
                                    +5.0%
                                </div>
                            </div>
                        </div>
                        <div class="ltr:ml-auto rtl:mr-auto max-w-[124px]">
                            <div id="spae-line3"></div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END::GROUP CHART 1 -->

            <!-- START::GROUP CHART 2 -->
            <div class="grid md:grid-cols-3 sm:grid-cols-2 grid-cols-1 gap-4">
                <!-- Totel revenue -->
                <div class="py-[18px] px-4 rounded-[6px] bg-[#E5F9FF] dark:bg-slate-900">
                    <div class="flex items-center space-x-6 rtl:space-x-reverse">
                        <div class="flex-none">
                            <div id="wline1"></div>
                        </div>
                        <div class="flex-1">
                            <div class="text-slate-800 dark:text-slate-300 text-sm mb-1 font-medium">
                                Totel revenue
                            </div>
                            <div class="text-slate-900 dark:text-white text-lg font-medium">
                                3,564
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Products sold -->
                <div class="py-[18px] px-4 rounded-[6px] bg-[#FFEDE5] dark:bg-slate-900">
                    <div class="flex items-center space-x-6 rtl:space-x-reverse">
                        <div class="flex-none">
                            <div id="wline2"></div>
                        </div>
                        <div class="flex-1">
                            <div class="text-slate-800 dark:text-slate-300 text-sm mb-1 font-medium">
                                Products sold
                            </div>
                            <div class="text-slate-900 dark:text-white text-lg font-medium">
                                3,564
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Growth -->
                <div class="py-[18px] px-4 rounded-[6px] bg-[#EAE5FF] dark:bg-slate-900">
                    <div class="flex items-center space-x-6 rtl:space-x-reverse">
                        <div class="flex-none">
                            <div id="wline3"></div>
                        </div>
                        <div class="flex-1">
                            <div class="text-slate-800 dark:text-slate-300 text-sm mb-1 font-medium">
                                Products sold
                            </div>
                            <div class="text-slate-900 dark:text-white text-lg font-medium">
                                +5.0%
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END::GROUP CHART 2 -->

            <!-- START:: GROUP CHART 3 -->
            <div class="card p-6">
                <div class="grid xl:grid-cols-4 lg:grid-cols-2 md:grid-cols-2 grid-cols-1 gap-5 place-content-center">
                    <div class="flex space-x-4 h-full items-center rtl:space-x-reverse">
                        <div class="flex-none">
                            <div class="h-20 w-20 rounded-full">
                                <img src="images/all-img/main-user.png" alt="" class="w-full h-full">
                            </div>
                        </div>
                        <div class="flex-1">
                            <h4 class="text-xl font-medium mb-2">
                                <span class="block font-light">Good evening,</span>
                                <span class="block">Mr. Jone Doe</span>
                            </h4>
                            <p class="text-sm dark:text-slate-300">Welcome to Dashcode</p>
                        </div>
                    </div>
                    <div class="bg-slate-50 dark:bg-slate-900 rounded p-4">
                        <div class="text-slate-600 dark:text-slate-400 text-sm mb-1 font-medium">
                            Current balance
                        </div>
                        <div class="text-slate-900 dark:text-white text-lg font-medium">
                            $34,564
                        </div>
                        <div class="ml-auto max-w-[124px]">
                            <div id="clmn_chart_1"></div>
                        </div>
                    </div>
                    <div class="bg-slate-50 dark:bg-slate-900 rounded p-4">
                        <div class="text-slate-600 dark:text-slate-400 text-sm mb-1 font-medium">
                            Credit
                        </div>
                        <div class="text-slate-900 dark:text-white text-lg font-medium">
                            $34,564
                        </div>
                        <div class="ml-auto max-w-[124px]">
                            <div id="clmn_chart_2"></div>
                        </div>
                    </div>
                    <div class="bg-slate-50 dark:bg-slate-900 rounded p-4">
                        <div class="text-slate-600 dark:text-slate-400 text-sm mb-1 font-medium">
                            Debit
                        </div>
                        <div class="text-slate-900 dark:text-white text-lg font-medium">
                            $34,564
                        </div>
                        <div class="ml-auto max-w-[124px]">
                            <div id="clmn_chart_3"></div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END:: GROUP CHART 3 -->

            <!-- START:: GROUP CHART 4 -->
            <div class="grid md:grid-cols-4 sm:grid-cols-2 grid-cols-1 gap-3">
                <div class="bg-warning-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-25 relative z-[1]">
                    <div class="overlay absolute left-0 top-0 w-full h-full z-[-1]">
                        <img src="images/all-img/shade-1.png" alt="" draggable="false"
                            class="w-full h-full object-contain">
                    </div>
                    <span class="block mb-6 text-sm text-slate-900 dark:text-white font-medium">
                        Sales
                    </span>
                    <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium mb-6">
                        354
                    </span>
                    <div class="flex space-x-2 rtl:space-x-reverse">
                        <div class="flex-none text-xl text-primary-500">
                            <iconify-icon icon="heroicons:arrow-trending-up"></iconify-icon>
                        </div>
                        <div class="flex-1 text-sm">
                            <span class="block mb-[2px] text-primary-500">
                                25.67%
                            </span>
                            <span class="block mb-1 text-slate-600 dark:text-slate-300">
                                From last week
                            </span>
                        </div>
                    </div>
                </div>
                <div class="bg-info-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-25 relative z-[1]">
                    <div class="overlay absolute left-0 top-0 w-full h-full z-[-1]">
                        <img src="images/all-img/shade-2.png" alt="" draggable="false"
                            class="w-full h-full object-contain">
                    </div>
                    <span class="block mb-6 text-sm text-slate-900 dark:text-white font-medium">
                        Revenue
                    </span>
                    <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium mb-6">
                        $86,954
                    </span>
                    <div class="flex space-x-2 rtl:space-x-reverse">
                        <div class="flex-none text-xl text-primary-500">
                            <iconify-icon icon="heroicons:arrow-trending-up"></iconify-icon>
                        </div>
                        <div class="flex-1 text-sm">
                            <span class="block mb-[2px] text-primary-500">
                                8.67%
                            </span>
                            <span class="block mb-1 text-slate-600 dark:text-slate-300">
                                From last week
                            </span>
                        </div>
                    </div>
                </div>
                <div class="bg-primary-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-25 relative z-[1]">
                    <div class="overlay absolute left-0 top-0 w-full h-full z-[-1]">
                        <img src="images/all-img/shade-3.png" alt="" draggable="false"
                            class="w-full h-full object-contain">
                    </div>
                    <span class="block mb-6 text-sm text-slate-900 dark:text-white font-medium">
                        Conversion
                    </span>
                    <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium mb-6">
                        15%
                    </span>
                    <div class="flex space-x-2 rtl:space-x-reverse">
                        <div class="flex-none text-xl text-primary-500">
                            <iconify-icon icon="heroicons:arrow-trending-up"></iconify-icon>
                        </div>
                        <div class="flex-1 text-sm">
                            <span class="block mb-[2px] text-primary-500">
                                1.67%
                            </span>
                            <span class="block mb-1 text-slate-600 dark:text-slate-300">
                                From last week
                            </span>
                        </div>
                    </div>
                </div>
                <div class="bg-success-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-25 relative z-[1]">
                    <div class="overlay absolute left-0 top-0 w-full h-full z-[-1]">
                        <img src="images/all-img/shade-4.png" alt="" draggable="false"
                            class="w-full h-full object-contain">
                    </div>
                    <span class="block mb-6 text-sm text-slate-900 dark:text-white font-medium">
                        Leads
                    </span>
                    <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium mb-6">
                        654
                    </span>
                    <div class="flex space-x-2 rtl:space-x-reverse">
                        <div class="flex-none text-xl text-primary-500">
                            <iconify-icon icon="heroicons:arrow-trending-up"></iconify-icon>
                        </div>
                        <div class="flex-1 text-sm">
                            <span class="block mb-[2px] text-primary-500">
                                11.67%
                            </span>
                            <span class="block mb-1 text-slate-600 dark:text-slate-300">
                                From last week
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END:: GROUP CHART 4 -->

            <!-- START:: GROUP CHART 5 -->
            <div class="grid md:grid-cols-4 sm:grid-cols-2 grid-cols-1 gap-3">
                <div class=" bg-info-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-50 text-center">
                    <div
                        class="text-info-500 mx-auto h-10 w-10 flex flex-col items-center justify-center rounded-full bg-white text-2xl mb-4">
                        <iconify-icon icon=heroicons-outline:menu-alt-1></iconify-icon>
                    </div>
                    <span class="block text-sm text-slate-600 font-medium dark:text-white mb-1">
                        Total Task
                    </span>
                    <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium">
                        64
                    </span>
                </div>
                <div class=" bg-warning-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-50 text-center">
                    <div
                        class="text-warning-500 mx-auto h-10 w-10 flex flex-col items-center justify-center rounded-full bg-white text-2xl mb-4">
                        <iconify-icon icon=heroicons-outline:chart-pie></iconify-icon>
                    </div>
                    <span class="block text-sm text-slate-600 font-medium dark:text-white mb-1">
                        Completed
                    </span>
                    <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium">
                        45
                    </span>
                </div>
                <div class=" bg-primary-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-50 text-center">
                    <div
                        class="text-primary-500 mx-auto h-10 w-10 flex flex-col items-center justify-center rounded-full bg-white text-2xl mb-4">
                        <iconify-icon icon=heroicons-outline:clock></iconify-icon>
                    </div>
                    <span class="block text-sm text-slate-600 font-medium dark:text-white mb-1">
                        Hours
                    </span>
                    <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium">
                        190
                    </span>
                </div>
                <div class=" bg-success-500 rounded-md p-4 bg-opacity-[0.15] dark:bg-opacity-50 text-center">
                    <div
                        class="text-success-500 mx-auto h-10 w-10 flex flex-col items-center justify-center rounded-full bg-white text-2xl mb-4">
                        <iconify-icon icon=heroicons-outline:calculator></iconify-icon>
                    </div>
                    <span class="block text-sm text-slate-600 font-medium dark:text-white mb-1">
                        Spendings
                    </span>
                    <span class="block mb- text-2xl text-slate-900 dark:text-white font-medium">
                        11.67%
                    </span>
                </div>
            </div>
            <!-- END:: GROUP CHART 5 -->

            <!-- START:: GROUP CHART 6 -->
            <div class="grid md:grid-cols-4 sm:grid-cols-2 grid-cols-1 gap-3">
                <div class="card p-6">
                    <span class="block text-slate-500 dark:text-slate-300 text-sm font-medium">
                        Progress
                    </span>
                    <div class="donut-chart" height="200" colors="#0CE7FA,#E2F6FD"></div>
                </div>
                <div class="card p-6">
                    <span class="block text-slate-500 dark:text-slate-300 text-sm font-medium">
                        Progress
                    </span>
                    <div class="donut-chart" height="200" colors="#50C793,#E5F3E5"></div>
                </div>
                <div class="card p-6">
                    <span class="block text-slate-500 dark:text-slate-300 text-sm font-medium">
                        Progress
                    </span>
                    <div class="donut-chart" height="200" colors="#FA916B,#fcc8b5"></div>
                </div>
                <div class="card p-6">
                    <span class="block text-slate-500 dark:text-slate-300 text-sm font-medium">
                        Progress
                    </span>
                    <div class="donut-chart" height="200" colors="#F1595C,#F9E1E5"></div>
                </div>
            </div>
            <!-- END:: GROUP CHART 6 -->

            <!-- START:: GROUP CHART 7 -->
            <div class="grid xl:grid-cols-6 lg:grid-cols-3 sm:grid-cols-2 grid-cols-1 gap-4">
                <div class="bg-white dark:bg-slate-800 rounded p-4">
                    <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                        Orders
                    </div>
                    <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                        123k
                    </div>
                    <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                        <span class="text-warning-500">-60%
                        </span>
                        From last Week
                    </div>
                    <div class="mt-4">
                        <div class="bar-chart" colors="#FA916B" height="44"></div>
                    </div>
                </div>
                <div class="bg-white dark:bg-slate-800 rounded p-4">
                    <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                        Orders
                    </div>
                    <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                        123k
                    </div>
                    <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                        <span class="text-warning-500">-60%
                        </span>
                        From last Week
                    </div>
                    <div class="mt-4">
                        <div class="bar-chart" colors="#50C793" height="44"></div>
                    </div>
                </div>
                <div class="bg-white dark:bg-slate-800 rounded p-4">
                    <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                        Orders
                    </div>
                    <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                        123k
                    </div>
                    <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                        <span class="text-warning-500">-60%
                        </span>
                        From last Week
                    </div>
                    <div class="mt-4">
                        <div class="bar-chart" colors="#F1595C" height="44"></div>
                    </div>
                </div>
                <div class="bg-white dark:bg-slate-800 rounded p-4">
                    <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                        Profit
                    </div>
                    <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                        654k
                    </div>
                    <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                        <span class="text-primary-500">+02%
                        </span>
                        From last Week
                    </div>
                    <div class="mt-4">
                        <div class="line-chart" colors="#FA916B" height="44"></div>
                    </div>
                </div>
                <div class="bg-white dark:bg-slate-800 rounded p-4">
                    <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                        Profit
                    </div>
                    <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                        654k
                    </div>
                    <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                        <span class="text-primary-500">+02%
                        </span>
                        From last Week
                    </div>
                    <div class="mt-4">
                        <div class="line-chart" colors="#F1595C" height="44"></div>
                    </div>
                </div>
                <div class="bg-white dark:bg-slate-800 rounded p-4">
                    <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                        Profit
                    </div>
                    <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                        654k
                    </div>
                    <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                        <span class="text-primary-500">+02%
                        </span>
                        From last Week
                    </div>
                    <div class="mt-4">
                        <div class="line-chart" colors="#50C793" height="44"></div>
                    </div>
                </div>
            </div>
            <!-- END:: GROUP CHART 7 -->

            <!-- START:: GROUP CHART 8 -->
            <div class="grid xl:grid-cols-3 lg:grid-cols-2 grid-cols-1 gap-4">
                <div class="bg-white dark:bg-slate-800 rounded py-3 px-4">
                    <div class="flex items-center">
                        <div class="flex-none">
                            <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                                Earnings
                            </div>
                            <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                                $12,335.00
                            </div>
                            <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                                <span class="text-primary-500">+08%</span>
                                From last Week
                            </div>
                        </div>
                        <div class="flex-1">
                            <div class="legend-ring2">
                                <div class="donut-chart" height="200" colors="#0CE7FA,#FA916B"
                                    hideLabel="hideLabel" size="65%"></div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="bg-white dark:bg-slate-800 rounded py-3 px-4">
                    <div class="flex items-center">
                        <div class="flex-none">
                            <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                                Earnings
                            </div>
                            <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                                $12,335.00
                            </div>
                            <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                                <span class="text-primary-500">+08%</span>
                                From last Week
                            </div>
                        </div>
                        <div class="flex-1">
                            <div class="legend-ring2">
                                <div class="donut-chart" height="200" colors="#4669FA,#50C793"
                                    hideLabel="hideLabel" size="65%"></div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="bg-white dark:bg-slate-800 rounded py-3 px-4">
                    <div class="flex items-center">
                        <div class="flex-none">
                            <div class="text-sm text-slate-600 dark:text-slate-300 mb-[6px]">
                                Earnings
                            </div>
                            <div class="text-lg text-slate-900 dark:text-white font-medium mb-[6px]">
                                $12,335.00
                            </div>
                            <div class="font-normal text-xs text-slate-600 dark:text-slate-300">
                                <span class="text-primary-500">+08%</span>
                                From last Week
                            </div>
                        </div>
                        <div class="flex-1">
                            <div class="legend-ring2">
                                <div class="donut-chart" height="200" colors="#F1595C,#0CE7FA"
                                    hideLabel="hideLabel" size="65%"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END:: GROUP CHART 8 -->
        </div>
    </div>

    @push('scripts')
        @vite(['resources/js/custom/chart-active.js'])
    @endpush
</x-app-layout>
