<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Basic Modal</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="flex items-center flex-wrap gap-5">
                            <button data-bs-toggle="modal" data-bs-target="#basic_modal" class="btn inline-flex justify-center btn-outline-dark capitalize">Basic Modal</button>
                            <button data-bs-toggle="modal" data-bs-target="#vertically_center" class="btn inline-flex justify-center btn-outline-dark">Vertically Center</button>
                            <button data-bs-toggle="modal" data-bs-target="#disabled_backdrop" class="btn inline-flex justify-center btn-outline-dark">Disabled Backdrop</button>
                            <button data-bs-toggle="modal" data-bs-target="#disabled_animation" class="btn inline-flex justify-center btn-outline-dark">Vertically Center</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Themes Modal Area Start -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Themes Modal</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="flex items-center flex-wrap gap-5">
                            <button data-bs-toggle="modal" data-bs-target="#primaryModal" class="btn inline-flex justify-center btn-outline-primary capitalize">primary</button>
                            <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="primaryModal" tabindex="-1" aria-labelledby="primaryModalLabel" aria-hidden="true" style="display: none;">
                                <div class="modal-dialog relative w-auto pointer-events-none">
                                    <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                                                    rounded-md outline-none text-current">
                                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                                            <!-- Modal header -->
                                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-primary-500">
                                                <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                            primary
                                            Modal
                                          </h3>
                                                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                                dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                                        11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                                    </svg> <span class="sr-only">Close modal</span> </button>
                                            </div>
                                            <!-- Modal body -->
                                            <div class="p-6 space-y-4">
                                                <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                            Lorem ipsum dolor sit.
                                          </h6>
                                                <p class="text-base text-slate-600 dark:text-slate-400 leading-6"> Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice. </p>
                                            </div>
                                            <!-- Modal footer -->
                                            <div class="flex items-center p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                                <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-primary-500">Accept</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <button data-bs-toggle="modal" data-bs-target="#secondaryModal" class="btn inline-flex justify-center btn-outline-secondary capitalize">secondary</button>
                            <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="secondaryModal" tabindex="-1" aria-labelledby="secondaryModalLabel" aria-hidden="true">
                                <div class="modal-dialog relative w-auto pointer-events-none">
                                    <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                                                    rounded-md outline-none text-current">
                                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                                            <!-- Modal header -->
                                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-secondary-500">
                                                <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                            secondary
                                            Modal
                                          </h3>
                                                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                                dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                                        11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                                    </svg> <span class="sr-only">Close modal</span> </button>
                                            </div>
                                            <!-- Modal body -->
                                            <div class="p-6 space-y-4">
                                                <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                            Lorem ipsum dolor sit.
                                          </h6>
                                                <p class="text-base text-slate-600 dark:text-slate-400 leading-6"> Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice. </p>
                                            </div>
                                            <!-- Modal footer -->
                                            <div class="flex items-center p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                                <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-secondary-500">Accept</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <button data-bs-toggle="modal" data-bs-target="#infoModal" class="btn inline-flex justify-center btn-outline-info capitalize">info</button>
                            <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="infoModal" tabindex="-1" aria-labelledby="infoModalLabel" aria-hidden="true">
                                <div class="modal-dialog relative w-auto pointer-events-none">
                                    <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                                                    rounded-md outline-none text-current">
                                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                                            <!-- Modal header -->
                                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-info-500">
                                                <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                            info
                                            Modal
                                          </h3>
                                                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                                dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                                        11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                                    </svg> <span class="sr-only">Close modal</span> </button>
                                            </div>
                                            <!-- Modal body -->
                                            <div class="p-6 space-y-4">
                                                <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                            Lorem ipsum dolor sit.
                                          </h6>
                                                <p class="text-base text-slate-600 dark:text-slate-400 leading-6"> Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice. </p>
                                            </div>
                                            <!-- Modal footer -->
                                            <div class="flex items-center p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                                <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-info-500">Accept</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <button data-bs-toggle="modal" data-bs-target="#successModal" class="btn inline-flex justify-center btn-outline-success capitalize">success</button>
                            <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="successModal" tabindex="-1" aria-labelledby="successModalLabel" aria-hidden="true">
                                <div class="modal-dialog relative w-auto pointer-events-none">
                                    <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                                                    rounded-md outline-none text-current">
                                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                                            <!-- Modal header -->
                                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-success-500">
                                                <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                            success
                                            Modal
                                          </h3>
                                                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                                dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                                        11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                                    </svg> <span class="sr-only">Close modal</span> </button>
                                            </div>
                                            <!-- Modal body -->
                                            <div class="p-6 space-y-4">
                                                <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                            Lorem ipsum dolor sit.
                                          </h6>
                                                <p class="text-base text-slate-600 dark:text-slate-400 leading-6"> Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice. </p>
                                            </div>
                                            <!-- Modal footer -->
                                            <div class="flex items-center p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                                <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-success-500">Accept</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <button data-bs-toggle="modal" data-bs-target="#warningModal" class="btn inline-flex justify-center btn-outline-warning capitalize">warning</button>
                            <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="warningModal" tabindex="-1" aria-labelledby="warningModalLabel" aria-hidden="true">
                                <div class="modal-dialog relative w-auto pointer-events-none">
                                    <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                                                    rounded-md outline-none text-current">
                                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                                            <!-- Modal header -->
                                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-warning-500">
                                                <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                            warning
                                            Modal
                                          </h3>
                                                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                                dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                                        11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                                    </svg> <span class="sr-only">Close modal</span> </button>
                                            </div>
                                            <!-- Modal body -->
                                            <div class="p-6 space-y-4">
                                                <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                            Lorem ipsum dolor sit.
                                          </h6>
                                                <p class="text-base text-slate-600 dark:text-slate-400 leading-6"> Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice. </p>
                                            </div>
                                            <!-- Modal footer -->
                                            <div class="flex items-center p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                                <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-warning-500">Accept</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <button data-bs-toggle="modal" data-bs-target="#dangerModal" class="btn inline-flex justify-center btn-outline-danger capitalize">danger</button>
                            <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="dangerModal" tabindex="-1" aria-labelledby="dangerModalLabel" aria-hidden="true">
                                <div class="modal-dialog relative w-auto pointer-events-none">
                                    <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                                                    rounded-md outline-none text-current">
                                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                                            <!-- Modal header -->
                                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-danger-500">
                                                <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                            danger
                                            Modal
                                          </h3>
                                                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                                dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                                        11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                                    </svg> <span class="sr-only">Close modal</span> </button>
                                            </div>
                                            <!-- Modal body -->
                                            <div class="p-6 space-y-4">
                                                <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                            Lorem ipsum dolor sit.
                                          </h6>
                                                <p class="text-base text-slate-600 dark:text-slate-400 leading-6"> Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice. </p>
                                            </div>
                                            <!-- Modal footer -->
                                            <div class="flex items-center p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                                <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-danger-500">Accept</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <button data-bs-toggle="modal" data-bs-target="#blackModal" class="btn inline-flex justify-center btn-outline-dark capitalize">black</button>
                            <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="blackModal" tabindex="-1" aria-labelledby="blackModalLabel" aria-hidden="true">
                                <div class="modal-dialog relative w-auto pointer-events-none">
                                    <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                                                    rounded-md outline-none text-current">
                                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                                            <!-- Modal header -->
                                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                                                <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                            black
                                            Modal
                                          </h3>
                                                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                                dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                                        11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                                    </svg> <span class="sr-only">Close modal</span> </button>
                                            </div>
                                            <!-- Modal body -->
                                            <div class="p-6 space-y-4">
                                                <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                            Lorem ipsum dolor sit.
                                          </h6>
                                                <p class="text-base text-slate-600 dark:text-slate-400 leading-6"> Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice. </p>
                                            </div>
                                            <!-- Modal footer -->
                                            <div class="flex items-center p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                                <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Themes Modal Area End -->
            <!-- Size Modal Area Start -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Size Modal</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="flex items-center flex-wrap gap-5">
                            <button data-bs-toggle="modal" data-bs-target="#small_modal" class="btn inline-flex justify-center btn-outline-dark capitalize">small Modal</button>
                            <button data-bs-toggle="modal" data-bs-target="#default_modal" class="btn inline-flex justify-center btn-outline-dark capitalize">default Modal</button>
                            <button data-bs-toggle="modal" data-bs-target="#large_modal" class="btn inline-flex justify-center btn-outline-dark capitalize">large Modal</button>
                            <button data-bs-toggle="modal" data-bs-target="#extra_large_modal" class="btn inline-flex justify-center btn-outline-dark capitalize">extra_large Modal</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Size Modal Area End -->
            <!-- Form & Scrolling Modals Area Start -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Form &amp; Scrolling Modals</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="flex items-center flex-wrap gap-5">
                            <button data-bs-toggle="modal" data-bs-target="#form_modal" class="btn inline-flex justify-center btn-outline-dark capitalize">Form Modal</button>
                            <button data-bs-toggle="modal" data-bs-target="#long_content_modal" class="btn inline-flex justify-center btn-outline-dark capitalize">Scrolling Long Modal</button>
                            <button data-bs-toggle="modal" data-bs-target="#scrollable_modal" class="btn inline-flex justify-center btn-outline-dark capitalize">Scrollable Modal</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Form & Scrolling Modals Area End -->
        </div>


        <!-- Basic Modal Area Start -->


        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="basic_modal" tabindex="-1" aria-labelledby="basic_modal" aria-hidden="true">
            <!-- BEGIN: Modal -->
            <div class="modal-dialog relative w-auto pointer-events-none">
              <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding rounded-md outline-none text-current">
                <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                  <!-- Modal header -->
                  <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                    <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                      Basic Modal
                    </h3>
                    <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                      <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                      </svg>
                      <span class="sr-only">Close modal</span>
                    </button>
                  </div>
                  <!-- Modal body -->
                  <div class="p-6 space-y-4">
                    <h6 class="text-base text-slate-900 dark:text-white leading-6">
                      Lorem ipsum dolor sit.
                    </h6>
                    <p class="text-base text-slate-600 dark:text-slate-400 leading-6">
                      Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice.
                    </p>
                  </div>
                  <!-- Modal footer -->
                  <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                    <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                  </div>
                </div>
              </div>
            </div>
            <!-- END: Modals -->
        </div>


        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="vertically_center" tabindex="-1" aria-labelledby="vertically_center" aria-hidden="true">
            <div class="modal-dialog top-1/2 !-translate-y-1/2 relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                        rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                Vertically Center
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                    dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                Lorem ipsum dolor sit.
                            </h6>
                            <p class="text-base text-slate-600 dark:text-slate-400 leading-6">
                                Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice.
                            </p>
                        </div>
                        <!-- Modal footer -->
                        <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                            <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="disabled_backdrop" tabindex="-1" aria-labelledby="disabled_backdrop" aria-hidden="true" data-bs-backdrop="static" data-bs-keyboard="false">
            <div class="modal-dialog relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                        rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                Disabled Backdrop
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                    dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                Lorem ipsum dolor sit.
                            </h6>
                            <p class="text-base text-slate-600 dark:text-slate-400 leading-6">
                                Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice.
                            </p>
                        </div>
                        <!-- Modal footer -->
                        <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                            <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="disabled_animation" tabindex="-1" aria-labelledby="disabled_animation" aria-hidden="true">
            <div class="modal-dialog top-0 !-translate-y-0 relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                        rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                Vertically Center
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                    dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                Lorem ipsum dolor sit.
                            </h6>
                            <p class="text-base text-slate-600 dark:text-slate-400 leading-6">
                                Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice.
                            </p>
                        </div>
                        <!-- Modal footer -->
                        <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                            <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Basic Modal Area End -->


        <!-- Size Modal Area Start -->
        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="small_modal" tabindex="-1" aria-labelledby="small_modal" aria-hidden="true">
            <div class="modal-dialog modal-sm relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                Small Modal
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                    dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                Lorem ipsum dolor sit.
                            </h6>
                            <p class="text-base text-slate-600 dark:text-slate-400 leading-6">
                                Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice.
                            </p>
                        </div>
                        <!-- Modal footer -->
                        <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                            <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="default_modal" tabindex="-1" aria-labelledby="default_modal" aria-hidden="true">
            <div class="modal-dialog relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                        rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                Default Modal
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                    dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                Lorem ipsum dolor sit.
                            </h6>
                            <p class="text-base text-slate-600 dark:text-slate-400 leading-6">
                                Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice.
                            </p>
                        </div>
                        <!-- Modal footer -->
                        <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                            <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="large_modal" tabindex="-1" aria-labelledby="large_modal" aria-hidden="true">
            <div class="modal-dialog modal-xl relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                        rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                Large Modal
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                    dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                Lorem ipsum dolor sit.
                            </h6>
                            <p class="text-base text-slate-600 dark:text-slate-400 leading-6">
                                Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice.
                            </p>
                        </div>
                        <!-- Modal footer -->
                        <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                            <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="extra_large_modal" tabindex="-1" aria-labelledby="extra_large_modal" aria-hidden="true">
            <div class="modal-dialog !max-w-full relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding
                        rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                Large Modal
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                    dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <h6 class="text-base text-slate-900 dark:text-white leading-6">
                                Lorem ipsum dolor sit.
                            </h6>
                            <p class="text-base text-slate-600 dark:text-slate-400 leading-6">
                                Oat cake ice cream candy chocolate cake apple pie. Brownie carrot cake candy canes. Cake sweet roll cake cheesecake cookie chocolate cake liquorice.
                            </p>
                        </div>
                        <!-- Modal footer -->
                        <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                            <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Accept</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Size Modal Area End -->


        <!-- Form Modal Area Start -->
        <div id="form_modal" tabindex="-1" aria-labelledby="form_modal" aria-hidden="true" class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto">
            <div class="modal-dialog modal-md relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding rounded-md outline-none text-current">
                    <div class="relative w-full h-full max-w-xl md:h-auto">
                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                            <!-- Modal header -->
                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                                <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                    Form Modal
                                </h3>
                                <button type="button" class="text-slate-400 bg-transparent hover:bg-slate-200 hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex
                                    items-center dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                    </svg>
                                    <span class="sr-only">Close modal</span>
                                </button>
                            </div>
                            <!-- Modal body -->
                            <div>
                                <form>
                                    <div class="p-6 space-y-6">
                                        <div class="input-group">
                                            <label for="name" class="text-sm font-Inter font-normal text-slate-900 block">Name:</label>
                                            <input type="text" id="name" class="text-sm font-Inter font-normal text-slate-600 block w-full py-3 px-4 focus:!outline-none focus:!ring-0 border
                                                !border-slate-400 rounded-md mt-2" placeholder="Type Your Email"></div>
                                        <div class="input-group">
                                            <label for="password" class="text-sm font-Inter font-normal text-slate-900 block">Password</label>
                                            <div class="relative" id="passwordInputField">
                                                <input type="password" id="password" class="passwordfield text-sm font-Inter font-normal text-slate-600 block w-full py-3 px-4 pr-9 focus:!outline-none
                                                        focus:!ring-0 border !border-slate-400 rounded-md mt-2" placeholder="Type Your Password" autocomplete="off">
                                                <span class="text-xl text-slate-400 absolute top-1/2 -translate-y-1/2 right-3 cursor-pointer" id="toggleIcon">
                                                    <iconify-icon id="hidePassword" icon="heroicons-outline:eye-off"></iconify-icon>
                                                    <iconify-icon class="hidden" id="showPassword" icon="heroicons-outline:eye"></iconify-icon>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    <!-- Modal footer -->
                                    <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                        <button data-bs-dismiss="modal" type="button" class="btn inline-flex justify-center btn-outline-dark">Close</button>
                                        <button data-bs-dismiss="modal" type="submit" class="btn inline-flex justify-center text-white bg-black-500">Log In</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Form Modal Area End -->


        <!-- long Content Modal Start -->
        <div id="long_content_modal" tabindex="-1" class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto">
            <div class="modal-dialog modal-md relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding rounded-md outline-none text-current">
                    <div class="relative w-full h-full max-w-2xl md:h-auto">
                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                            <!-- Modal header -->
                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                                <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                    Scrolling Long Content Modal
                                </h3>
                                <button type="button" class="text-slate-400 bg-transparent hover:bg-slate-200 hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex
                                            items-center dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                    11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                    </svg>
                                    <span class="sr-only">Close modal</span>
                                </button>
                            </div>
                            <!-- Modal body -->
                            <div class="p-6 space-y-6">
                                <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Perspiciatis, ipsum non? Voluptatem et reprehenderit necessitatibus, atque ad a cupiditate! Alias voluptates quam voluptas quisquam corporis aliquid minima maiores consectetur sunt iusto, rem fugiat sed omnis corrupti culpa blanditiis vel deserunt placeat possimus voluptate ab facere eius. Rem eligendi minus commodi?</p>
                                <p>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Aliquam eveniet ab fuga eius eaque ex alias non. Beatae earum magni minima labore? Accusamus provident ipsam eos consectetur eveniet doloribus omnis aliquam perferendis quibusdam, maiores, id, odio aut temporibus quae ea voluptatum quidem! Quibusdam a ipsam tempora, provident nisi unde cupiditate reiciendis assumenda sed ullam aperiam quam velit culpa molestias dolore nihil natus dolorem voluptatibus! Aut veritatis eos perferendis, itaque eveniet exercitationem enim perspiciatis blanditiis ducimus, magnam aperiam tempora quaerat nulla quasi sapiente. Minima beatae, impedit nobis quod velit aperiam ullam atque vitae vero nostrum rerum, natus alias est? Temporibus, tempora!</p>
                                <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Perspiciatis, ipsum non? Voluptatem et reprehenderit necessitatibus, atque ad a cupiditate! Alias voluptates quam voluptas quisquam corporis aliquid minima maiores consectetur sunt iusto, rem fugiat sed omnis corrupti culpa blanditiis vel deserunt placeat possimus voluptate ab facere eius. Rem eligendi minus commodi?</p>
                                <p>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Aliquam eveniet ab fuga eius eaque ex alias non. Beatae earum magni minima labore? Accusamus provident ipsam eos consectetur eveniet doloribus omnis aliquam perferendis quibusdam, maiores, id, odio aut temporibus quae ea voluptatum quidem! Quibusdam a ipsam tempora, provident nisi unde cupiditate reiciendis assumenda sed ullam aperiam quam velit culpa molestias dolore nihil natus dolorem voluptatibus! Aut veritatis eos perferendis, itaque eveniet exercitationem enim perspiciatis blanditiis ducimus, magnam aperiam tempora quaerat nulla quasi sapiente. Minima beatae, impedit nobis quod velit aperiam ullam atque vitae vero nostrum rerum, natus alias est? Temporibus, tempora!</p>
                                <p>Lorem ipsum dolor sit amet consectetur, adipisicing elit. Mollitia debitis error quod? Quidem adipisci consectetur ea necessitatibus nisi, repellendus natus in excepturi ab repudiandae accusamus impedit soluta. Eligendi veniam, vitae libero perferendis tempore blanditiis quis quod ex architecto iste ipsam labore soluta vel ducimus porro nam quaerat rerum tenetur perspiciatis, a sequi. Libero quis omnis quo eligendi exercitationem quidem modi mollitia, natus illo veritatis in nulla nesciunt sint, recusandae deleniti.</p>
                                <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Optio tenetur libero sit cumque eum alias, voluptates at est numquam velit!</p>
                            </div>
                            <!-- Modal footer -->
                            <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                <button data-bs-dismiss="modal" type="submit" class="btn inline-flex justify-center text-white bg-black-500">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- long Content Modal End -->


        <!-- Scrollable Modal Start -->
        <div id="scrollable_modal" tabindex="-1" class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto">
            <div class="modal-dialog modal-md relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col w-full pointer-events-auto bg-white bg-clip-padding rounded-md outline-none text-current">
                    <div class="relative w-full h-full max-w-2xl md:h-auto">
                        <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                            <!-- Modal header -->
                            <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                                <h3 class="text-xl font-medium text-white dark:text-white capitalize">
                                    Scrollable Content Modal
                                </h3>
                                <button type="button" class="text-slate-400 bg-transparent hover:bg-slate-200 hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                                                11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                    </svg>
                                    <span class="sr-only">Close modal</span>
                                </button>
                            </div>
                            <!-- Modal body -->
                            <div class="p-6 space-y-6 max-h-[calc(100vh-200px)] overflow-y-auto" id="scrollModal">
                                <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Perspiciatis, ipsum non? Voluptatem et reprehenderit necessitatibus, atque ad a cupiditate! Alias voluptates quam voluptas quisquam corporis aliquid minima maiores consectetur sunt iusto, rem fugiat sed omnis corrupti culpa blanditiis vel deserunt placeat possimus voluptate ab facere eius. Rem eligendi minus commodi?</p>
                                <p>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Aliquam eveniet ab fuga eius eaque ex alias non. Beatae earum magni minima labore? Accusamus provident ipsam eos consectetur eveniet doloribus omnis aliquam perferendis quibusdam, maiores, id, odio aut temporibus quae ea voluptatum quidem! Quibusdam a ipsam tempora, provident nisi unde cupiditate reiciendis assumenda sed ullam aperiam quam velit culpa molestias dolore nihil natus dolorem voluptatibus! Aut veritatis eos perferendis, itaque eveniet exercitationem enim perspiciatis blanditiis ducimus, magnam aperiam tempora quaerat nulla quasi sapiente. Minima beatae, impedit nobis quod velit aperiam ullam atque vitae vero nostrum rerum, natus alias est? Temporibus, tempora!</p>
                                <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Perspiciatis, ipsum non? Voluptatem et reprehenderit necessitatibus, atque ad a cupiditate! Alias voluptates quam voluptas quisquam corporis aliquid minima maiores consectetur sunt iusto, rem fugiat sed omnis corrupti culpa blanditiis vel deserunt placeat possimus voluptate ab facere eius. Rem eligendi minus commodi?</p>
                                <p>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Aliquam eveniet ab fuga eius eaque ex alias non. Beatae earum magni minima labore? Accusamus provident ipsam eos consectetur eveniet doloribus omnis aliquam perferendis quibusdam, maiores, id, odio aut temporibus quae ea voluptatum quidem! Quibusdam a ipsam tempora, provident nisi unde cupiditate reiciendis assumenda sed ullam aperiam quam velit culpa molestias dolore nihil natus dolorem voluptatibus! Aut veritatis eos perferendis, itaque eveniet exercitationem enim perspiciatis blanditiis ducimus, magnam aperiam tempora quaerat nulla quasi sapiente. Minima beatae, impedit nobis quod velit aperiam ullam atque vitae vero nostrum rerum, natus alias est? Temporibus, tempora!</p>
                                <p>Lorem ipsum dolor sit amet consectetur, adipisicing elit. Mollitia debitis error quod? Quidem adipisci consectetur ea necessitatibus nisi, repellendus natus in excepturi ab repudiandae accusamus impedit soluta. Eligendi veniam, vitae libero perferendis tempore blanditiis quis quod ex architecto iste ipsam labore soluta vel ducimus porro nam quaerat rerum tenetur perspiciatis, a sequi. Libero quis omnis quo eligendi exercitationem quidem modi mollitia, natus illo veritatis in nulla nesciunt sint, recusandae deleniti.</p>
                                <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Optio tenetur libero sit cumque eum alias, voluptates at est numquam velit!</p>
                            </div>
                            <!-- Modal footer -->
                            <div class="flex items-center justify-end p-6 space-x-2 border-t border-slate-200 rounded-b dark:border-slate-600">
                                <button data-bs-dismiss="modal" type="submit" class="btn inline-flex justify-center text-white bg-black-500">
                                    Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Scrollable Modal End -->
    </div>
</x-app-layout>
