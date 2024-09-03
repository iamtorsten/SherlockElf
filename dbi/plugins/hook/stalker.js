var active = true;

// Stalker
function stalk(pattern)
{
	var type = (pattern.indexOf(' ') === -1) ? 'module' : 'objc';
	var res = new ApiResolver(type);
	var matches = res.enumerateMatchesSync(pattern);
	var targets = uniqBy(matches, JSON.stringify);

	targets.forEach(function(target) {
		stalkFunction(target.address, target.name);
	});
}

function uniqBy(array, key)
{
	var seen = {};
	return array.filter(function(item) {
		var k = key(item);
		return seen.hasOwnProperty(k) ? false : (seen[k] = true);
	});
}

function stalkFunction(impl, name)
{
	console.log("Stalking " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			if (active)
				return;

			var flag = {};
			this.flag = flag;

			active = true;

			Stalker.follow({

				events: {
					call:	true,
					ret:	true,
					exec:	true
				},

				onCallSummary: function (summary) {
					console.log();
					Object.keys(summary).forEach(function (target) {
						console.log(name + " > " + DebugSymbol.fromAddress(ptr(target)).toString());
						flag[target] = true;
					});
				}

			});
		},

		onLeave: function(retval) {
			var flag = this.flag;
			if (flag === undefined)
				return;

			// Deactivate
			Stalker.unfollow();
			active = false;
		}
	});
}

if (ObjC.available) {

	stalk("*[OWSMessageSender *]");
	stalk("-[OWSMessageSender attemptToSendMessage*]");
	stalk("-[OWSMessageSender tag]");
	stalk("exports:libSystem.B.dylib!open");
	stalk("exports:*!open*");

} else {
 	send("error: Objective-C Runtime is not available!");
}