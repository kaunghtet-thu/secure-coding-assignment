var validator=require('validator');

var validationFn={
  validateListingInputData: function (req, res, next) {
    
    const xssRegex = /^[\w\s.,!?()-]{1,1000}$/; // Strong Regular expression to check for XSS attacks

    var title = req.body.title;
    var category = req.body.category;
    var description = req.body.description;
    var price = req.body.price;

    // Validate title, category, and description
    if (!xssRegex.test(title) || !xssRegex.test(category) || !xssRegex.test(description)){
      var error = { error: "Title, category and description can only contain letters, numbers, spaces, and basic punctuation (.,!?()-). Special characters and HTML tags are not allowed." };
      console.error(error);
      return res.status(400).json(error);
    }
  
    // Validate price
    if (!price || isNaN(price) || price < 0 || price > 10000) {
      var error = { error: "Price must be a number between 0 and 10000." };
      console.error(error);
      return res.status(400).json(error);
    }
  
    next();
  },

  sanitizeResult: function (result) {
  return result.map((record) => {
      for (const key in record) {
          if (typeof record[key] === "string") {
              record[key] = validator.escape(record[key]); // Escapes HTML characters
          }
      }
      return record;
  });
  }


}

module.exports=validationFn;

