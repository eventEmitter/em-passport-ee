!function(){

	var   Class 				= require('ee-class')
		, EventEmitter 			= require('ee-event-emitter')
		, log 					= require('ee-log')
		, RandomDataProvider 	= require('ee-random-data-provider');


	// random data for all instances
	var randomData = new RandomDataProvider();



	module.exports = new Class({
		inherits: EventEmitter


		// urls sent to the client when the authorization failed
		, _headers: { 'WWW-Authenticate': 'ee' }

		// regexp to find the authorization
		, _authRegExp: /ee\s+([a-z0-9]+)/gi

		// the length an ee token must have
		, tokenLength: 128 


		/**
		 * passport contructor funtion
		 *
		 * @param <Object> options
		 */
		, init: function(options){
			if( options.authorizationUrl ) this._headers.Location = options.authorizationUrl;
			if( options.regexp ) this._authRegExp = options.regexp;
			if( options.tokenLength ) this.tokenLength = options.tokenLength;
		}

		
		/**
		 * the setAuthorizationHandler() method is called by the em-passport middleware
		 * it passes the authorization class to this middleware
		 *
		 * @param <Function> class Authorization
		 */
		, setAuthorizationHandler: function(Authorization){
			this._Authorization = Authorization;
		}


		/**
		 * the createToken() method creates a secure random token
		 * this may require a random d ata generator harware token
		 * on higher service loads
		 *
		 * @param <Function> callback
		 * @param <Boolean> usePseudoRandom, if its ok to use pseudorandom data if the
		 * 				    random data pool gets drain
		 */
		, createToken: function(callback, usePseudoRandom){
			if (usePseudoRandom) {
				callback(randomData.get(this.tokenLength));
			}
			else randomData.get(this.tokenLength, callback);
		}



		/**
		 * the request() method handles requests
		 *
		 * @param <Object> request
		 * @param <Object> response
		 * @param <Function> callback
		 */
		, request: function(request, response, next){
			var   header = request.getHeader('authorization')
				, token;

			// the authroization must be located in the authorization header
			if (header){
				this._authRegExp.lastIndex = 0;

				// extract header
				token = this._authRegExp.exec(header);

				// extraction ok, correct length?
				if (token && token.length === 2 && token[1] && token[1].length === this.tokenLength){

					// store the authorization token
					request.authorization.token = token[1];

					// ask the user function to provide authentiacation info
					this.emit('authorization', request.authorization, function(err){
						if (err) {
							response.send(500);
							log.error('Error during ee authentication processing!');
							log.trace(err);
						}
						else if (request.authorization.authorized) next();
						else response.send(401, this._headers);
					}.bind(this));
				}
				else response.send(401, this._headers);
			}
			else response.send(401, this._headers);		
		}
	});

}();