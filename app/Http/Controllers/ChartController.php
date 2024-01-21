<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ChartController extends Controller
{

    /**
     * chart view
     */
    public function index()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Chart',
                'url' => '/chart',
                'active' => true
            ],
        ];
        return view('elements.chart.chart', [
            'pageTitle' => 'Chart',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }



    /**
     * chart view
     */
    public function apexchart()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Apexchart',
                'url' => '/chart-apex',
                'active' => true
            ],
        ];
        return view('elements.chart.apexchart', [
            'pageTitle' => 'Apexchart',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


}
