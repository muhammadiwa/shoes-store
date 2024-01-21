<x-app-layout>
    <div class="space-y-8">
        <div>
            <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-5">

            <!-- BEGIN: Bar Chart -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Bar Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <canvas id="chart1" class="h-[350px]"></canvas>
                </div>
            </div>
            <!-- END: Bar Chart -->

            <!-- BEGIN: Horizontal Bar -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Horizontal Bar
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <canvas id="chart2" class="h-[350px]"></canvas>
                </div>
            </div>
            <!-- END: Horizontal Bar -->

            <!-- BEGIN: Bar Stacked -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Bar Stacked
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <canvas id="chart3" class="h-[350px]"></canvas>
                </div>
            </div>
            <!-- END: Bar Stacked -->

            <!-- BEGIN: Line Chart -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Line Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <canvas id="chart4" class="h-[350px]"></canvas>
                </div>
            </div>
            <!-- END: Line Chart -->

            <!-- BEGIN: Radar Chart -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Radar Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <canvas id="chart5" class="h-[350px]"></canvas>
                </div>
            </div>
            <!-- END: Radar Chart -->

            <!-- BEGIN: Poller Area Chart -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Poller Area Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <canvas id="chart6" class="h-[350px]"></canvas>
                </div>
            </div>
            <!-- END: Poller Area Chart -->
        </div>
    </div>

    @push('scripts')
        @vite(['resources/js/custom/chart-active.js'])
    @endpush
</x-app-layout>
