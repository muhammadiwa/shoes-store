<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="card">
            <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                        <div class="card-title text-slate-900 dark:text-white">Input Mask</div>
                    </div>
                </header>
                <div class="card-text h-full ">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <div class="input-area">
                            <label for="creditCard" class="form-label">Credit Card</label>
                            <input id="creditCard" type="text" class="form-control" placeholder="0000 0000 0000 0000"> </div>
                        <div class="input-area">
                            <label for="phone" class="form-label">Phone Number</label>
                            <input id="phone" type="text" class="form-control" placeholder="Phone Number"> </div>
                        <div class="input-area">
                            <label for="date" class="form-label">Date</label>
                            <input id="date" type="text" class="form-control" placeholder="YYYY/MM/DD"> </div>
                        <div class="input-area">
                            <label for="time" class="form-label">Time</label>
                            <input id="time" type="text" class="form-control" placeholder="HH:MM:SS"> </div>
                        <div class="input-area">
                            <label for="numeralFormatting" class="form-label">Numeral Formatting</label>
                            <input id="numeralFormatting" type="text" class="form-control" placeholder="10,000"> </div>
                        <div class="input-area">
                            <label for="blocks" class="form-label">Blocks</label>
                            <input id="blocks" type="text" class="form-control" placeholder="6543 454 484"> </div>
                        <div class="input-area">
                            <label for="delimiters" class="form-label">Delimiters</label>
                            <input id="delimiters" type="text" class="form-control" placeholder="615.645.658"> </div>
                        <div class="input-area">
                            <label for="customdelimiters" class="form-label">Custom Delimiters</label>
                            <input id="customdelimiters" type="text" class="form-control" placeholder="Delimiter: ['.', '.', '-']"> </div>
                        <div class="input-area">
                            <label for="prefix" class="form-label">Prefix</label>
                            <input id="prefix" type="text" class="form-control" placeholder="+88 5485487478"> </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    @push('scripts')
        <script type="module">
            // Credit Card
            new Cleave('#creditCard', {
                creditCard: true
            });
            // Phone
            new Cleave('#phone', {
                prefix: '+88 ',
                delimiter: '-',
                blocks: [8, 7],
                numericOnly: true
            });
            // Date
            new Cleave('#date', {
                date: true,
                delimiter: '/',
                datePattern: ['Y', 'm', 'd']
            });
            // Time
            new Cleave('#time', {
                time: true,
                timePattern: ['h', 'm', 's']
            });
            // Numeral Formatting
            new Cleave('#numeralFormatting', {
                numeral: true,
                numeralThousandsGroupStyle: 'thousand'
            });
            // Blocks
            new Cleave('#blocks', {
                blocks: [4, 3, 3, 4],
                uppercase: true
            });
            // Delimiters
            new Cleave('#delimiters', {
                delimiter: '.',
                blocks: [3, 3, 3],
                uppercase: true
            });
            // Custom Delimiters
            new Cleave('#customdelimiters', {
                delimiters: ['.', '/', '-'],
                blocks: [3, 3, 3, 2],
                uppercase: true
            });
            // Prefix
            new Cleave('#prefix', {
                prefix: '+88 ',
                delimiter: '-',
                blocks: [6, 4, 4, 4],
                uppercase: true
            });
        </script>
    @endpush
</x-app-layout>
