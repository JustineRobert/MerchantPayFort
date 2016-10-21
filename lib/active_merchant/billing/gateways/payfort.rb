require 'digest'
require 'json'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class PayfortGateway < Gateway
      class_attribute :credit_card_tokenization_test_url, :credit_card_tokenization_live_url

      self.credit_card_tokenization_test_url = 'https://sbcheckout.PayFort.com/FortAPI/paymentPage'
      self.credit_card_tokenization_live_url = 'https://checkout.PayFort.com/FortAPI/paymentPage'

      self.test_url = 'https://sbpaymentservices.payfort.com/FortAPI/paymentApi'
      self.live_url = 'https://paymentservices.payfort.com/FortAPI/paymentApi'

      self.supported_countries = ['AE']
      self.money_format = :cents
      self.default_currency = 'AED'
      self.supported_cardtypes = [:visa, :master]

      self.homepage_url = 'http://www.payfort.com/'
      self.display_name = 'Payfort'

      STANDARD_ERROR_CODE_MAPPING = {}

      def initialize(options={})
        requires!(options, :merchant_identifier, :access_code, :sha_request_phrase, :language)
        super
      end

      def purchase(money, payment, options={})
        post = {}
        post[:command] = 'PURCHASE'

        add_invoice(post, money, options)
        add_payment(post, payment)
        add_customer_data(post, options)
        add_mandatory_fields(post, options)
        add_optional_fields(post, options)
        add_security_settings(post, payment)

        commit('PURCHASE', post)
      end

      def authorize(money, payment, options={})
        post = {}
        add_invoice(post, money, options)
        add_payment(post, payment)
        add_address(post, payment, options)
        add_customer_data(post, options)

        commit('authonly', post)
      end

      def capture(money, authorization, options={})
        commit('capture', post)
      end

      def refund(money, authorization, options={})
        commit('refund', post)
      end

      def void(authorization, options={})
        commit('void', post)
      end

      def verify(credit_card, options={})
        MultiResponse.run(:use_first_response) do |r|
          r.process { authorize(100, credit_card, options) }
          r.process(:ignore_result) { void(r.authorization, options) }
        end
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript
      end

      def store(credit_card, parameters={})
        post = {}

        post[:service_command] = 'TOKENIZATION'
        post[:merchant_identifier] = self.options[:merchant_identifier]
        post[:access_code] = self.options[:access_code]
        post[:merchant_reference] = parameters[:order_id]
        post[:language] = self.options[:language]
        # NOTE: credit card token will be sent to return url as GET parameter
        post[:return_url] = parameters[:return_url]
        post[:merchant_extra] = parameters[:merchant_extra]
        post[:signature] = signature(post)

        post[:remember_me] = parameters[:remember_me] ? 'YES' : 'NO'
        post[:card_number] = credit_card.number
        post[:expiry_date] = "#{credit_card.year.to_s[-2,2]}#{credit_card.month.to_s.rjust(2, '0')}"
        post[:card_security_code] = credit_card.verification_value if credit_card.verification_value?
        post[:card_holder_name] = credit_card.name if credit_card.name

        url = test? ? self.class.credit_card_tokenization_test_url : self.class.credit_card_tokenization_live_url
        ssl_post(url, post_data('TOKENIZATION', post), headers('TOKENIZATION'))
      end

      private

      def add_customer_data(post, options)
        post[:customer_email] = options[:customer_email]
        # post[:customer_ip] = options[:customer_ip]
      end

      def add_address(post, creditcard, options)
      end

      def add_invoice(post, money, options)
        post[:amount] = amount(money)
        post[:currency] = (options[:currency] || currency(money))
      end

      # NOTE: card_security_code should not be present in JSON
      def add_payment(post, payment)
        post[:token_name] = payment.token
        post[:customer_name] = payment.name
      end

      def add_mandatory_fields(post, options)
        post[:merchant_reference] = options[:order_id]
        post[:language] = self.options[:language]
      end

      def add_optional_fields(post, options)
        post[:merchant_extra] = options[:merchant_extra] if options[:merchant_extra]
      end

      def add_security_settings(post, payment)
        post[:merchant_identifier] = self.options[:merchant_identifier]
        post[:access_code] = self.options[:access_code]
        post[:signature] = signature(post)
      end

      def parse(body)
        JSON.parse(body)
      end

      def commit(action, parameters)
        url = (test? ? test_url : live_url)
        response = parse(ssl_post(url, post_data(action, parameters), headers(action)))

        Response.new(
          success_from(response, action),
          message_from(response),
          response,
          authorization: authorization_from(response),
          test: test?
        )
      end

      def success_from(response, action)
        if action == 'PURCHASE'
          response['status'] == '14' &&
          response['response_code'] == "14000"
        end
      end

      def message_from(response)
        response['response_message']
      end

      def authorization_from(response)
        response['authorization_code']
      end

      def post_data(action, parameters={})
        return JSON.fast_generate(parameters) if action == 'PURCHASE'

        parameters.map do |key, value|
          escaped_value = CGI.escape(value.to_s)
          "#{key}=#{escaped_value}"
        end.join('&')
      end

      def handle_response(response)
        case response.code.to_i
        when 200...300
          response.body
        when 302
          ssl_get(URI.parse(response['location']))
        else
          raise ResponseError.new(response)
        end
      end

      def headers(action)
        headers = {}
        headers['Accept-Encoding'] = 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3'

        case action
        when 'PURCHASE'
          json = 'application/json'
          headers['Accept'] = json
          headers['Content-Type'] = "#{json}; charset=utf-8"
        when 'TOKENIZATION'
          urlencoded = 'application/x-www-form-urlencoded'
          headers['Accept'] = urlencoded
          headers['Content-Type'] = "#{urlencoded}; charset=utf-8"
        end
        headers
      end

      def signature(args={})
        salt = self.options[:sha_request_phrase]
        str = args.sort.reduce(salt) {|memo, (k,v)| memo += "#{k}=#{v}"} << salt
        Digest::SHA256.hexdigest(str).upcase
      end
    end
  end
end
