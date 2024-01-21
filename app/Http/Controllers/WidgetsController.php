<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class WidgetsController extends Controller
{
    /**
     * Widget Basic
     */
    public function basic()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Widget Basic',
                'url' => '/widget-basic',
                'active' => true
            ],

        ];
        return view('elements.widgets.basic', [
            'pageTitle' => 'Basic Widget',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


    /**
     * Statistic Basic
     */
    public function statistic()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Widget Statistic',
                'url' => '/widget-statistic',
                'active' => true
            ],

        ];
        return view('elements.widgets.statistic', [
            'pageTitle' => 'Statistic Widget',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }
}
