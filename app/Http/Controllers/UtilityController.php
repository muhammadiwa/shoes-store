<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UtilityController extends Controller
{

    /**
     * Invoice
     */
    public function invoice()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Invoice',
                'url' => '/invoice',
                'active' => true
            ],

        ];
        return view('utility.invoice', [
            'pageTitle' => 'Invoice',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


    /**
     * Pricing
     */
    public function pricing()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Pricing',
                'url' => '/pricing',
                'active' => true
            ],

        ];
        return view('utility.pricing', [
            'pageTitle' => 'Pricing',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Blog
     */
    public function blog()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Blog',
                'url' => '/blog',
                'active' => true
            ],

        ];
        return view('utility.blog', [
            'pageTitle' => 'Blog',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Blog Details
     */
    public function blogDetails()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Blog Details',
                'url' => '/blog-details',
                'active' => true
            ],

        ];
        return view('utility.blog-details', [
            'pageTitle' => 'Blog Details',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }



    /**
     * Blog Details
     */
    public function blank()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Blank',
                'url' => '/blank',
                'active' => true
            ],

        ];
        return view('utility.blank', [
            'pageTitle' => 'Blank',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }



    /**
     * Profile
     */
    public function profile()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Profile',
                'url' => '/profile',
                'active' => true
            ],

        ];
        return view('utility.profile', [
            'pageTitle' => 'Profile',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }




    /**
     * error404
     */
    public function error404()
    {
        $breadcrumbsItems = [
            [
                'name' => 'error404',
                'url' => '/utility-404',
                'active' => true
            ],

        ];
        return view('utility.404', [
            'pageTitle' => 'Error 404',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }




    /**
     * Coming soon
     */
    public function comingSoon()
    {
        $breadcrumbsItems = [
            [
                'name' => 'comingSoon',
                'url' => '/coming-soon',
                'active' => true
            ],

        ];
        return view('utility.coming-soon', [
            'pageTitle' => 'Coming Soon',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }



    /**
     * Under maintenance
     */
    public function underMaintenance()
    {
        $breadcrumbsItems = [
            [
                'name' => 'underMaintenance',
                'url' => '/under-maintenance',
                'active' => true
            ],

        ];
        return view('utility.under-maintenance', [
            'pageTitle' => 'Under Maintenance',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }
}
