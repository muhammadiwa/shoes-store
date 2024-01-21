<x-app-layout>
    <div class="space-y-8">
        <div>
            <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-5">
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Area Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="areaChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Area Spaline
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="areaSpaline"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Basic Bar Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="basicBarChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Column Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="columnChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">3D Bubble
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="bubbleChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Scatter Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="scatterChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Candlestick Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="candlestickChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Stepline Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="steplineChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Stacked Columns
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="stackedColumns"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Pie & Donut Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div class="grid xl:grid-cols-2 grid-cols-1 gap-5">
                        <div>
                            <div id="pieChart"></div>
                        </div>
                        <div>
                            <div id="donutChart"></div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Mixed Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="mixedChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Radar Chart
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="radarChart"></div>
                </div>
            </div>
            <!-- end single card -->
            <div class="card">
                <header class=" card-header">
                    <h4 class="card-title">Multiple Radialbars
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div id="radialbars"></div>
                </div>
            </div>
            <!-- end single card -->
        </div>
    </div>

    @push('scripts')
        @vite(['resources/js/custom/chart-active.js'])
    @endpush
</x-app-layout>
