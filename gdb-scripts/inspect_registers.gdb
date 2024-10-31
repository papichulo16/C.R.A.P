define run_binary
	file "$arg0"

	if $argc == 3
		break *$arg2
	end

	run <<< "$arg1"

	info registers

	quit
end

