<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class TableController extends Controller
{

    /**
     * Basic table
     */
    public function basic()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Basic table',
                'url' => '/table-basic',
                'active' => true
            ],

        ];

        $tableData = [
            [
                'id' => 1,
                'age' => 82,
                'first_name' => "Dorelle",
                'last_name' => "Harling",
                'email' => "dharling0@rediff.com",
                'gender' => "Female",
                'phone' => "232(152)707-0110",
                'ccupation' => "Financial Advisor"
            ],
            [
                'id' => 2,
                'age' => 89,
                'first_name' => "Bendicty",
                'last_name' => "Llewellin",
                'email' => "bllewellin1@example.com",
                'gender' => "Male",
                'phone' => "420(169)218-1769",
                'ccupation' => "Marketing Assistant"
            ],
            [
                'id' => 3,
                'age' => 28,
                'first_name' => "Remy",
                'last_name' => "Carbry",
                'email' => "rcarbry2@prlog.org",
                'gender' => "Polygender",
                'phone' => "86(958)204-4491",
                'ccupation' => "Mechanical Systems Engineer"
            ],
            [
                'id' => 4,
                'age' => 20,
                'first_name' => "Bernardo",
                'last_name' => "Hacun",
                'email' => "bhacun3@xinhuanet.com",
                'gender' => "Male",
                'phone' => "86(974)709-5254",
                'ccupation' => "Research Assistant IV"
            ],
            [
                'id' => 5,
                'age' => 2,
                'first_name' => "Emelia",
                'last_name' => "Garstang",
                'email' => "egarstang4@miitbeian.gov.cn",
                'gender' => "Female",
                'phone' => "55(644)175-6748",
                'ccupation' => "Business Systems Development Analyst"
            ],
            [
                'id' => 6,
                'age' => 98,
                'first_name' => "Dian",
                'last_name' => "Dopson",
                'email' => "ddopson5@examiner.com",
                'gender' => "Female",
                'phone' => "51(186)560-8480",
                'ccupation' => "Cost Accountant"
            ],
            [
                'id' => 7,
                'age' => 17,
                'first_name' => "Coretta",
                'last_name' => "Ponter",
                'email' => "cponter6@loc.gov",
                'gender' => "Female",
                'phone' => "1(941)734-6255",
                'ccupation' => "Budget/Accounting Analyst II"
            ]
        ];

        return view('elements.tables.basic', [
            'pageTitle' => 'Basic table',
            'tableData' => $tableData,
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }



    /**
     * Advance table
     */
    public function advance()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Basic table',
                'url' => '/table-basic',
                'active' => true
            ],

        ];


        $tableData = [
            [
              "id"=> 1,
              "order"=> 951,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "3/26/2022",
              "quantity"=> 13,
              "amount"=> "$1779.53",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 2,
              "order"=> 238,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "2/6/2022",
              "quantity"=> 13,
              "amount"=> "$2215.78",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 3,
              "order"=> 339,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "9/6/2021",
              "quantity"=> 1,
              "amount"=> "$3183.60",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 4,
              "order"=> 365,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "11/7/2021",
              "quantity"=> 13,
              "amount"=> "$2587.86",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 5,
              "order"=> 513,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "5/6/2022",
              "quantity"=> 12,
              "amount"=> "$3840.73",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 6,
              "order"=> 534,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "2/14/2022",
              "quantity"=> 12,
              "amount"=> "$4764.18",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 7,
              "order"=> 77,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "7/30/2022",
              "quantity"=> 6,
              "amount"=> "$2875.05",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 8,
              "order"=> 238,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "6/30/2022",
              "quantity"=> 9,
              "amount"=> "$2491.02",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 9,
              "order"=> 886,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "8/9/2022",
              "quantity"=> 8,
              "amount"=> "$3006.95",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 10,
              "order"=> 3,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "8/4/2022",
              "quantity"=> 12,
              "amount"=> "$2160.32",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 11,
              "order"=> 198,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "4/5/2022",
              "quantity"=> 8,
              "amount"=> "$1272.66",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 12,
              "order"=> 829,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "8/9/2022",
              "quantity"=> 2,
              "amount"=> "$4327.86",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 13,
              "order"=> 595,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "2/10/2022",
              "quantity"=> 11,
              "amount"=> "$3671.81",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 14,
              "order"=> 374,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "2/10/2022",
              "quantity"=> 2,
              "amount"=> "$3401.82",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 15,
              "order"=> 32,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "5/20/2022",
              "quantity"=> 4,
              "amount"=> "$2387.49",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 16,
              "order"=> 89,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "5/3/2022",
              "quantity"=> 15,
              "amount"=> "$4236.61",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 17,
              "order"=> 912,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "10/31/2021",
              "quantity"=> 11,
              "amount"=> "$2975.66",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 18,
              "order"=> 621,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "1/13/2022",
              "quantity"=> 5,
              "amount"=> "$4576.13",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 19,
              "order"=> 459,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "6/14/2022",
              "quantity"=> 5,
              "amount"=> "$1276.56",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 20,
              "order"=> 108,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "10/8/2021",
              "quantity"=> 4,
              "amount"=> "$1078.64",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 21,
              "order"=> 492,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "11/17/2021",
              "quantity"=> 9,
              "amount"=> "$1678.19",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 22,
              "order"=> 42,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "4/4/2022",
              "quantity"=> 9,
              "amount"=> "$1822.02",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 23,
              "order"=> 841,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "3/21/2022",
              "quantity"=> 5,
              "amount"=> "$1578.39",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 24,
              "order"=> 561,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "6/18/2022",
              "quantity"=> 12,
              "amount"=> "$2130.49",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 25,
              "order"=> 720,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "8/15/2022",
              "quantity"=> 8,
              "amount"=> "$3721.11",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 26,
              "order"=> 309,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "4/28/2022",
              "quantity"=> 8,
              "amount"=> "$4683.45",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 27,
              "order"=> 24,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "9/6/2021",
              "quantity"=> 7,
              "amount"=> "$2863.71",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 28,
              "order"=> 518,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "9/11/2021",
              "quantity"=> 4,
              "amount"=> "$3879.41",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 29,
              "order"=> 98,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "1/27/2022",
              "quantity"=> 5,
              "amount"=> "$4660.81",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 30,
              "order"=> 940,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "9/16/2021",
              "quantity"=> 6,
              "amount"=> "$4800.75",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 31,
              "order"=> 925,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "1/8/2022",
              "quantity"=> 1,
              "amount"=> "$2299.05",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 32,
              "order"=> 122,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "11/18/2021",
              "quantity"=> 1,
              "amount"=> "$3578.02",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 33,
              "order"=> 371,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "3/30/2022",
              "quantity"=> 13,
              "amount"=> "$1996.06",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 34,
              "order"=> 296,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "11/13/2021",
              "quantity"=> 5,
              "amount"=> "$2749.00",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 35,
              "order"=> 887,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "12/7/2021",
              "quantity"=> 11,
              "amount"=> "$4353.01",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 36,
              "order"=> 30,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "9/9/2021",
              "quantity"=> 15,
              "amount"=> "$3252.37",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 37,
              "order"=> 365,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "2/12/2022",
              "quantity"=> 5,
              "amount"=> "$4044.10",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 38,
              "order"=> 649,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "3/6/2022",
              "quantity"=> 5,
              "amount"=> "$3859.92",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 39,
              "order"=> 923,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "7/25/2022",
              "quantity"=> 14,
              "amount"=> "$1652.47",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 40,
              "order"=> 423,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "3/2/2022",
              "quantity"=> 8,
              "amount"=> "$2700.12",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 41,
              "order"=> 703,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "12/8/2021",
              "quantity"=> 8,
              "amount"=> "$4508.13",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 42,
              "order"=> 792,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "11/22/2021",
              "quantity"=> 11,
              "amount"=> "$4938.04",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 43,
              "order"=> 400,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "4/6/2022",
              "quantity"=> 1,
              "amount"=> "$3471.32",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 44,
              "order"=> 718,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "2/4/2022",
              "quantity"=> 4,
              "amount"=> "$4011.60",
              "status"=> "paid",
              "action"=> null
            ],
            [
              "id"=> 45,
              "order"=> 970,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "3/30/2022",
              "quantity"=> 15,
              "amount"=> "$3723.64",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 46,
              "order"=> 786,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "11/20/2021",
              "quantity"=> 2,
              "amount"=> "$2441.15",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 47,
              "order"=> 925,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "10/24/2021",
              "quantity"=> 11,
              "amount"=> "$1196.76",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 48,
              "order"=> 929,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "6/30/2022",
              "quantity"=> 10,
              "amount"=> "$3579.57",
              "status"=> "cancled",
              "action"=> null
            ],
            [
              "id"=> 49,
              "order"=> 377,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "11/16/2021",
              "quantity"=> 4,
              "amount"=> "$2657.84",
              "status"=> "due",
              "action"=> null
            ],
            [
              "id"=> 50,
              "order"=> 661,
              "customer"=> [
                "name"=> "Jenny Wilson",
                "image"=> "customer_1.png"
              ],
              "date"=> "8/15/2022",
              "quantity"=> 6,
              "amount"=> "$2905.94",
              "status"=> "paid",
              "action"=> null
            ]
          ];

        return view('elements.tables.advance', [
            'pageTitle' => 'Basic table',
            'tableData' => $tableData,
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }
}
